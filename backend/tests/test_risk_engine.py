"""Tests for app/services/risk_engine.py"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Alert, Base, Entity, Incident
from app.services.risk_engine import priority_band, score_alert_risk


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_maker() as s:
        yield s
    await engine.dispose()


def make_alert(**overrides) -> Alert:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source="test-source",
        source_product="generic_webhook",
        severity="medium",
    )
    defaults.update(overrides)
    return Alert(**defaults)


async def _save(session, obj):
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return obj


@pytest.mark.parametrize(
    "score,expected",
    [(0, "low"), (29, "low"), (30, "medium"), (59, "medium"), (60, "high"), (84, "high"), (85, "critical"), (100, "critical")],
)
def test_priority_band(score, expected):
    assert priority_band(score) == expected


@pytest.mark.asyncio
async def test_score_reflects_severity_base(session: AsyncSession):
    low = await _save(session, make_alert(severity="low"))
    critical = await _save(session, make_alert(severity="critical"))

    low = await score_alert_risk(session, low)
    critical = await score_alert_risk(session, critical)

    assert low.risk_score < critical.risk_score
    assert low.risk_score_breakdown["severity_base"] == 20
    assert critical.risk_score_breakdown["severity_base"] == 85


@pytest.mark.asyncio
async def test_score_unknown_severity_uses_fallback(session: AsyncSession):
    alert = await _save(session, make_alert(severity="unknown"))
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score_breakdown["severity_base"] == 30


@pytest.mark.asyncio
async def test_mitre_mapping_adds_bonus(session: AsyncSession):
    plain = await _save(session, make_alert(severity="medium"))
    with_mitre = await _save(
        session,
        make_alert(severity="medium", existing_mitre_attack_mapping=[{"technique_id": "T1059.001"}]),
    )

    plain = await score_alert_risk(session, plain)
    with_mitre = await score_alert_risk(session, with_mitre)

    assert with_mitre.risk_score == plain.risk_score + 10
    assert with_mitre.risk_score_breakdown["mitre_mapping_bonus"] == 10
    assert plain.risk_score_breakdown["mitre_mapping_bonus"] == 0


@pytest.mark.asyncio
async def test_correlated_alerts_add_bonus_capped(session: AsyncSession):
    incident = await _save(session, Incident(title="test incident"))
    alert = await _save(session, make_alert(severity="medium", incident_id=incident.id))
    # add 10 sibling alerts in the same incident to test the bonus cap
    for _ in range(10):
        await _save(session, make_alert(severity="low", incident_id=incident.id))

    alert = await score_alert_risk(session, alert)
    assert alert.risk_score_breakdown["correlated_alert_count"] == 10
    assert alert.risk_score_breakdown["correlation_bonus"] == 15  # capped at 15, not 30


@pytest.mark.asyncio
async def test_uncorrelated_alert_has_zero_correlation_bonus(session: AsyncSession):
    alert = await _save(session, make_alert(severity="medium"))
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score_breakdown["correlation_bonus"] == 0
    assert alert.risk_score_breakdown["correlated_alert_count"] == 0


@pytest.mark.asyncio
async def test_critical_asset_hostname_adds_bonus(session: AsyncSession):
    await _save(session, Entity(entity_type="host", value="CRITICAL-SERVER", criticality="critical"))
    alert = await _save(session, make_alert(severity="medium", hostname="CRITICAL-SERVER"))
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score_breakdown["asset_criticality_bonus"] == 15


@pytest.mark.asyncio
async def test_unknown_hostname_has_zero_criticality_bonus(session: AsyncSession):
    alert = await _save(session, make_alert(severity="medium", hostname="UNKNOWN-HOST"))
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score_breakdown["asset_criticality_bonus"] == 0


@pytest.mark.asyncio
async def test_privileged_user_adds_bonus(session: AsyncSession):
    await _save(session, Entity(entity_type="user", value="admin.j", privilege_level="domain_admin"))
    alert = await _save(session, make_alert(severity="medium", username="admin.j"))
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score_breakdown["user_privilege_bonus"] == 10


@pytest.mark.asyncio
async def test_score_never_exceeds_max(session: AsyncSession):
    await _save(session, Entity(entity_type="host", value="H1", criticality="critical"))
    await _save(session, Entity(entity_type="user", value="U1", privilege_level="domain_admin"))
    incident = await _save(session, Incident(title="big incident"))
    for _ in range(10):
        await _save(session, make_alert(severity="critical", incident_id=incident.id))

    alert = await _save(
        session,
        make_alert(
            severity="critical",
            hostname="H1",
            username="U1",
            incident_id=incident.id,
            existing_mitre_attack_mapping=[{"technique_id": "T1059.001"}],
        ),
    )
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score <= 100


@pytest.mark.asyncio
async def test_investigation_priority_matches_score_band(session: AsyncSession):
    alert = await _save(session, make_alert(severity="critical"))
    alert = await score_alert_risk(session, alert)
    assert alert.investigation_priority == priority_band(alert.risk_score)


@pytest.mark.asyncio
async def test_rescoring_recomputes_rather_than_accumulates(session: AsyncSession):
    """Calling score_alert_risk twice on the same alert (e.g. after a
    later correlation pass changes its incident) must recompute from
    scratch, not add another severity_base on top of the first score."""
    alert = await _save(session, make_alert(severity="medium"))
    alert = await score_alert_risk(session, alert)
    first_score = alert.risk_score
    alert = await score_alert_risk(session, alert)
    assert alert.risk_score == first_score
