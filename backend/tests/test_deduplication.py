"""Tests for app/services/deduplication.py"""

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Alert, Base
from app.services.deduplication import compute_signature, deduplicate_alert


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


def test_compute_signature_deterministic_regardless_of_field_order():
    a1 = make_alert(hostname="H1", username="U1", rule_id="R1")
    a2 = make_alert(hostname="H1", username="U1", rule_id="R1")  # same values, different object
    assert compute_signature(a1) == compute_signature(a2)


def test_compute_signature_differs_when_values_differ():
    a1 = make_alert(hostname="H1")
    a2 = make_alert(hostname="H2")
    assert compute_signature(a1) != compute_signature(a2)


def test_compute_signature_none_when_no_entity_keys():
    assert compute_signature(make_alert()) is None


@pytest.mark.asyncio
async def test_deduplicate_first_alert_becomes_own_group_leader(session: AsyncSession):
    alert = await _save(session, make_alert(hostname="H1", rule_id="R1"))
    result = await deduplicate_alert(session, alert)
    assert result.dedup_group_id == result.alert_id


@pytest.mark.asyncio
async def test_deduplicate_second_matching_alert_joins_first_groups(session: AsyncSession):
    now = datetime.now(timezone.utc)
    first = await _save(session, make_alert(hostname="H1", rule_id="R1", timestamp=now))
    first = await deduplicate_alert(session, first)

    second = await _save(session, make_alert(hostname="H1", rule_id="R1", timestamp=now + timedelta(seconds=30)))
    second = await deduplicate_alert(session, second)

    assert second.dedup_group_id == first.dedup_group_id == first.alert_id


@pytest.mark.asyncio
async def test_deduplicate_outside_window_does_not_group(session: AsyncSession):
    now = datetime.now(timezone.utc)
    first = await _save(session, make_alert(hostname="H1", rule_id="R1", timestamp=now))
    first = await deduplicate_alert(session, first)

    later = await _save(
        session, make_alert(hostname="H1", rule_id="R1", timestamp=now + timedelta(minutes=30))
    )
    later = await deduplicate_alert(session, later, window_minutes=5)

    assert later.dedup_group_id == later.alert_id  # own group, too far outside window


@pytest.mark.asyncio
async def test_deduplicate_no_entity_keys_never_groups_with_anything(session: AsyncSession):
    now = datetime.now(timezone.utc)
    a1 = await _save(session, make_alert(timestamp=now))
    a1 = await deduplicate_alert(session, a1)
    a2 = await _save(session, make_alert(timestamp=now))
    a2 = await deduplicate_alert(session, a2)

    assert a1.dedup_group_id == a1.alert_id
    assert a2.dedup_group_id == a2.alert_id
    assert a1.dedup_group_id != a2.dedup_group_id


@pytest.mark.asyncio
async def test_deduplicate_third_alert_joins_established_group(session: AsyncSession):
    """A group formed by alerts 1+2 should also absorb alert 3, not create
    a second group — this is the actual "500 alerts -> 1 group" scenario."""
    now = datetime.now(timezone.utc)
    ids = []
    for i in range(3):
        a = await _save(session, make_alert(hostname="H1", rule_id="R1", timestamp=now + timedelta(seconds=i)))
        a = await deduplicate_alert(session, a)
        ids.append(a.dedup_group_id)
    assert len(set(ids)) == 1
