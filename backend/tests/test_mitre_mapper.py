"""Tests for app/services/mitre/mapper.py"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import AIAnalysis, Alert, Base, MitreTechnique
from app.services.mitre.mapper import get_technique_details, map_alert_to_mitre, validate_technique_ids


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_maker() as s:
        yield s
    await engine.dispose()


async def _seed_techniques(session):
    session.add_all(
        [
            MitreTechnique(technique_id="T1059.001", name="PowerShell", tactic="Execution"),
            MitreTechnique(technique_id="T1566", name="Phishing", tactic="Initial Access"),
        ]
    )
    await session.commit()


def make_alert(**overrides) -> Alert:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source="test-source",
        source_product="generic_webhook",
    )
    defaults.update(overrides)
    return Alert(**defaults)


async def _save(session, obj):
    session.add(obj)
    await session.commit()
    await session.refresh(obj)
    return obj


# --- validate_technique_ids -------------------------------------------------

@pytest.mark.asyncio
async def test_validate_splits_valid_and_invalid(session: AsyncSession):
    await _seed_techniques(session)
    valid, invalid = await validate_technique_ids(session, ["T1059.001", "T9999-fake"])
    assert valid == ["T1059.001"]
    assert invalid == ["T9999-fake"]


@pytest.mark.asyncio
async def test_validate_empty_input(session: AsyncSession):
    valid, invalid = await validate_technique_ids(session, [])
    assert valid == []
    assert invalid == []


@pytest.mark.asyncio
async def test_validate_deduplicates(session: AsyncSession):
    await _seed_techniques(session)
    valid, invalid = await validate_technique_ids(session, ["T1059.001", "T1059.001", "T1059.001"])
    assert valid == ["T1059.001"]


# --- get_technique_details -------------------------------------------------

@pytest.mark.asyncio
async def test_get_technique_details_preserves_order(session: AsyncSession):
    await _seed_techniques(session)
    details = await get_technique_details(session, ["T1566", "T1059.001"])
    assert [t.technique_id for t in details] == ["T1566", "T1059.001"]


# --- map_alert_to_mitre -------------------------------------------------

@pytest.mark.asyncio
async def test_map_alert_combines_vendor_and_ai_claims(session: AsyncSession):
    await _seed_techniques(session)
    alert = await _save(
        session,
        make_alert(existing_mitre_attack_mapping=[{"technique_id": "T1566", "technique_name": "Phishing"}]),
    )
    analysis = AIAnalysis(
        alert_id=alert.alert_id,
        provider="fake",
        model="fake",
        classification="x",
        risk_score=50,
        confidence=0.5,
        investigation_priority="medium",
        summary="s",
        mitre_techniques=[{"technique_id": "T1059.001"}],
    )

    mapping = await map_alert_to_mitre(session, alert, analysis)
    ids = {t["technique_id"] for t in mapping["techniques"]}
    assert ids == {"T1566", "T1059.001"}
    assert mapping["invalid_technique_ids"] == []


@pytest.mark.asyncio
async def test_map_alert_flags_invalid_technique_id_instead_of_hiding_it(session: AsyncSession):
    await _seed_techniques(session)
    alert = await _save(
        session, make_alert(existing_mitre_attack_mapping=[{"technique_id": "T0000-not-real"}])
    )
    mapping = await map_alert_to_mitre(session, alert, ai_analysis=None)
    assert mapping["techniques"] == []
    assert mapping["invalid_technique_ids"] == ["T0000-not-real"]


@pytest.mark.asyncio
async def test_map_alert_with_no_claims_at_all(session: AsyncSession):
    alert = await _save(session, make_alert())
    mapping = await map_alert_to_mitre(session, alert, ai_analysis=None)
    assert mapping == {"techniques": [], "invalid_technique_ids": []}


@pytest.mark.asyncio
async def test_map_alert_enriches_with_full_technique_detail(session: AsyncSession):
    await _seed_techniques(session)
    alert = await _save(
        session, make_alert(existing_mitre_attack_mapping=[{"technique_id": "T1059.001"}])
    )
    mapping = await map_alert_to_mitre(session, alert, ai_analysis=None)
    assert mapping["techniques"][0]["name"] == "PowerShell"
    assert mapping["techniques"][0]["tactic"] == "Execution"
