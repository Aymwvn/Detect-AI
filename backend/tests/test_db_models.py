"""
Integration tests for the DB models. Uses an in-memory SQLite engine so
these run with zero external dependencies — the real Alembic migration
against Postgres is verified separately (see migrations/versions/).
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import AIAnalysis, Alert, AnalystFeedback, Base, Event, Incident


@pytest_asyncio.fixture
async def session() -> AsyncSession:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_maker() as s:
        yield s

    await engine.dispose()


@pytest.mark.asyncio
async def test_create_alert_minimal(session: AsyncSession):
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        source="test-source",
        source_product="generic_webhook",
    )
    session.add(alert)
    await session.commit()

    result = await session.execute(select(Alert))
    fetched = result.scalar_one()
    assert fetched.severity == "unknown"
    assert fetched.status == "new"
    assert fetched.tags == []


@pytest.mark.asyncio
async def test_alert_with_events_and_ai_analysis(session: AsyncSession):
    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        source="test-source",
        source_product="elastic_security",
        severity="high",
        hostname="WIN10-TEST",
        process_name="powershell.exe",
    )
    session.add(alert)
    await session.flush()

    event = Event(
        alert_id=alert.alert_id,
        timestamp=datetime.now(timezone.utc),
        event_type="process_start",
        description="powershell.exe launched",
        raw_event={"pid": 1234},
    )
    analysis = AIAnalysis(
        alert_id=alert.alert_id,
        provider="ollama",
        model="llama3",
        classification="likely_malicious",
        risk_score=87,
        confidence=0.91,
        investigation_priority="high",
        summary="Test summary",
        evidence=[{"event_id": event.id}],
    )
    session.add_all([event, analysis])
    await session.commit()

    result = await session.execute(select(Alert).where(Alert.alert_id == alert.alert_id))
    fetched = result.scalar_one()
    await session.refresh(fetched, attribute_names=["events", "ai_analyses"])

    assert len(fetched.events) == 1
    assert fetched.events[0].event_type == "process_start"
    assert len(fetched.ai_analyses) == 1
    assert fetched.ai_analyses[0].risk_score == 87


@pytest.mark.asyncio
async def test_incident_groups_alerts(session: AsyncSession):
    incident = Incident(title="Office -> PowerShell -> Network chain", mitre_techniques=["T1566", "T1059.001"])
    session.add(incident)
    await session.flush()

    alert1 = Alert(
        timestamp=datetime.now(timezone.utc),
        source="s1",
        source_product="generic_webhook",
        incident_id=incident.id,
    )
    alert2 = Alert(
        timestamp=datetime.now(timezone.utc),
        source="s1",
        source_product="generic_webhook",
        incident_id=incident.id,
    )
    session.add_all([alert1, alert2])
    await session.commit()

    result = await session.execute(select(Incident).where(Incident.id == incident.id))
    fetched = result.scalar_one()
    await session.refresh(fetched, attribute_names=["alerts"])
    assert len(fetched.alerts) == 2
    assert fetched.mitre_techniques == ["T1566", "T1059.001"]


@pytest.mark.asyncio
async def test_analyst_feedback_linked_to_alert(session: AsyncSession):
    alert = Alert(timestamp=datetime.now(timezone.utc), source="s1", source_product="generic_webhook")
    session.add(alert)
    await session.flush()

    feedback = AnalystFeedback(alert_id=alert.alert_id, analyst_id="analyst-1", label="false_positive", comment="IT automation")
    session.add(feedback)
    await session.commit()

    result = await session.execute(select(AnalystFeedback).where(AnalystFeedback.alert_id == alert.alert_id))
    fetched = result.scalar_one()
    assert fetched.label == "false_positive"
