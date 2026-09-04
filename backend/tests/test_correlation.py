"""Tests for app/services/correlation.py"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Alert, Base, Incident
from app.services.correlation import correlate_alert


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
    )
    defaults.update(overrides)
    return Alert(**defaults)


async def _save(session, alert):
    session.add(alert)
    await session.commit()
    await session.refresh(alert)
    return alert


@pytest.mark.asyncio
async def test_single_alert_no_correlation_no_incident(session: AsyncSession):
    alert = await _save(session, make_alert(hostname="H1"))
    result = await correlate_alert(session, alert)
    assert result.incident_id is None


@pytest.mark.asyncio
async def test_two_alerts_sharing_host_create_one_incident(session: AsyncSession):
    now = datetime.now(timezone.utc)
    first = await _save(session, make_alert(hostname="H1", rule_name="Phishing email", timestamp=now))
    second = await _save(
        session,
        make_alert(hostname="H1", rule_name="PowerShell execution", timestamp=now + timedelta(minutes=5)),
    )

    first = await correlate_alert(session, first)
    second = await correlate_alert(session, second)

    assert first.incident_id is not None
    assert first.incident_id == second.incident_id

    result = await session.execute(select(Incident).where(Incident.id == first.incident_id))
    incident = result.scalar_one()
    assert "H1" in incident.title


@pytest.mark.asyncio
async def test_third_alert_joins_existing_incident(session: AsyncSession):
    """Attack chain: alert 1 + 2 form an incident; alert 3 (sharing the
    same host, arriving later) should join that SAME incident, not create
    a second one — this is the actual attack-chain-reconstruction case."""
    now = datetime.now(timezone.utc)
    a1 = await _save(session, make_alert(hostname="H1", timestamp=now))
    a2 = await _save(session, make_alert(hostname="H1", timestamp=now + timedelta(minutes=5)))
    a1 = await correlate_alert(session, a1)
    a2 = await correlate_alert(session, a2)

    a3 = await _save(session, make_alert(hostname="H1", timestamp=now + timedelta(minutes=10)))
    a3 = await correlate_alert(session, a3)

    assert a3.incident_id == a1.incident_id == a2.incident_id

    result = await session.execute(select(Incident))
    all_incidents = result.scalars().all()
    assert len(all_incidents) == 1


@pytest.mark.asyncio
async def test_alerts_sharing_different_entity_still_correlate(session: AsyncSession):
    """Two alerts with no shared hostname but the same destination_ip
    (e.g. two different hosts beaconing to the same C2) should still
    correlate — that's the point of the "ANY shared entity" match."""
    now = datetime.now(timezone.utc)
    a1 = await _save(session, make_alert(hostname="H1", destination_ip="10.0.0.1", timestamp=now))
    a2 = await _save(
        session, make_alert(hostname="H2", destination_ip="10.0.0.1", timestamp=now + timedelta(minutes=1))
    )
    a1 = await correlate_alert(session, a1)
    a2 = await correlate_alert(session, a2)
    assert a1.incident_id == a2.incident_id


@pytest.mark.asyncio
async def test_alerts_outside_window_do_not_correlate(session: AsyncSession):
    now = datetime.now(timezone.utc)
    a1 = await _save(session, make_alert(hostname="H1", timestamp=now))
    a1 = await correlate_alert(session, a1)

    a2 = await _save(session, make_alert(hostname="H1", timestamp=now + timedelta(hours=48)))
    a2 = await correlate_alert(session, a2, window_hours=24)

    assert a2.incident_id is None


@pytest.mark.asyncio
async def test_alerts_with_no_entity_context_never_correlate(session: AsyncSession):
    now = datetime.now(timezone.utc)
    a1 = await _save(session, make_alert(timestamp=now))
    a2 = await _save(session, make_alert(timestamp=now))
    a1 = await correlate_alert(session, a1)
    a2 = await correlate_alert(session, a2)
    assert a1.incident_id is None
    assert a2.incident_id is None


@pytest.mark.asyncio
async def test_unrelated_alerts_do_not_correlate(session: AsyncSession):
    now = datetime.now(timezone.utc)
    a1 = await _save(session, make_alert(hostname="H1", timestamp=now))
    a2 = await _save(session, make_alert(hostname="H2", destination_ip="9.9.9.9", timestamp=now))
    a1 = await correlate_alert(session, a1)
    a2 = await correlate_alert(session, a2)
    assert a1.incident_id is None
    assert a2.incident_id is None
