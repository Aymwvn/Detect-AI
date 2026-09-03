"""
Tests for app/services/ingestion.py.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Alert, Base
from app.schemas import CommonAlertSchema, ExistingMitreMapping, SourceProduct
from app.services.ingestion import find_existing_alert, ingest_alert, ingest_from_connector_poll
from connectors.base import RawAlert, SIEMConnector


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    async with session_maker() as s:
        yield s
    await engine.dispose()


def make_schema(**overrides) -> CommonAlertSchema:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source="test-source",
        source_product=SourceProduct.GENERIC_WEBHOOK,
        hostname="TEST-HOST",
    )
    defaults.update(overrides)
    return CommonAlertSchema(**defaults)


@pytest.mark.asyncio
async def test_ingest_alert_persists_all_fields(session: AsyncSession):
    schema = make_schema(external_alert_id="ext-1", severity="high", process_name="powershell.exe", tags=["a", "b"])
    db_alert = await ingest_alert(session, schema)

    assert db_alert.alert_id == schema.alert_id
    assert db_alert.hostname == "TEST-HOST"
    assert db_alert.severity == "high"
    assert db_alert.tags == ["a", "b"]

    result = await session.execute(select(Alert).where(Alert.alert_id == schema.alert_id))
    fetched = result.scalar_one()
    assert fetched.process_name == "powershell.exe"


@pytest.mark.asyncio
async def test_ingest_alert_idempotent_on_source_and_external_id(session: AsyncSession):
    schema1 = make_schema(external_alert_id="dup-1")
    schema2 = make_schema(external_alert_id="dup-1")  # different alert_id, same source+external_alert_id

    first = await ingest_alert(session, schema1)
    second = await ingest_alert(session, schema2)

    assert first.alert_id == second.alert_id  # second call returned the existing row, no duplicate

    result = await session.execute(select(Alert).where(Alert.source == "test-source"))
    assert len(result.scalars().all()) == 1


@pytest.mark.asyncio
async def test_ingest_alert_without_external_id_never_deduplicates(session: AsyncSession):
    await ingest_alert(session, make_schema())
    await ingest_alert(session, make_schema())

    result = await session.execute(select(Alert).where(Alert.source == "test-source"))
    assert len(result.scalars().all()) == 2


@pytest.mark.asyncio
async def test_find_existing_alert_returns_none_when_absent(session: AsyncSession):
    found = await find_existing_alert(session, "test-source", "does-not-exist")
    assert found is None


@pytest.mark.asyncio
async def test_ingest_alert_preserves_nested_mitre_mapping(session: AsyncSession):
    schema = make_schema(
        existing_mitre_attack_mapping=[
            ExistingMitreMapping(technique_id="T1059.001", technique_name="PowerShell", tactic="Execution")
        ]
    )
    db_alert = await ingest_alert(session, schema)
    assert db_alert.existing_mitre_attack_mapping[0]["technique_id"] == "T1059.001"


class _PollMockConnector(SIEMConnector):
    source_product = SourceProduct.GENERIC_WEBHOOK.value

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._raws: list[RawAlert] = [
            {"hostname": "good-host"},
            {"__malformed__": True},
        ]

    def authenticate(self) -> bool:
        return True

    def fetch_alerts(self, since):
        return self._raws

    def normalize_event(self, raw: RawAlert) -> CommonAlertSchema:
        if raw.get("__malformed__"):
            raise ValueError("simulated malformed alert")
        return make_schema(hostname=raw["hostname"], source="poll-source")


@pytest.mark.asyncio
async def test_ingest_from_connector_poll_skips_malformed_without_crashing(session: AsyncSession):
    connector = _PollMockConnector(connector_id="c1", name="poll-source")
    ingested = await ingest_from_connector_poll(session, connector, since=datetime.now(timezone.utc))
    assert len(ingested) == 1
    assert ingested[0].hostname == "good-host"
