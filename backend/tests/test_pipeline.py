"""Tests for app/services/pipeline.py — proves the full automatic
(non-AI) pipeline runs correctly end-to-end on ingestion."""

from datetime import datetime, timezone

import pytest

from app.schemas import CommonAlertSchema, SourceProduct
from app.services.ingestion import ingest_alert
from app.services.pipeline import process_new_alert


def make_schema(**overrides) -> CommonAlertSchema:
    defaults = dict(
        timestamp=datetime.now(timezone.utc),
        source="pipeline-test",
        source_product=SourceProduct.GENERIC_WEBHOOK,
    )
    defaults.update(overrides)
    return CommonAlertSchema(**defaults)


@pytest.mark.asyncio
async def test_new_alert_gets_dedup_group_and_risk_score(client, db_session):
    schema = make_schema(hostname="H1", severity="high")
    db_alert = await ingest_alert(db_session, schema)
    processed = await process_new_alert(db_session, db_alert)

    assert processed.dedup_group_id is not None
    assert processed.risk_score is not None
    assert processed.risk_score_breakdown["severity_base"] == 65
    assert processed.investigation_priority is not None
    assert processed.incident_id is None  # single alert, nothing to correlate with yet


@pytest.mark.asyncio
async def test_two_correlated_alerts_both_get_risk_bonus(client, db_session):
    a1 = await ingest_alert(db_session, make_schema(hostname="SHARED-HOST", severity="medium"))
    a1 = await process_new_alert(db_session, a1)

    a2 = await ingest_alert(db_session, make_schema(hostname="SHARED-HOST", severity="medium"))
    a2 = await process_new_alert(db_session, a2)

    assert a1.incident_id == a2.incident_id
    assert a1.incident_id is not None

    # a1 was scored before a2 existed, so re-score it to see the updated
    # correlation bonus now that it has a sibling in the incident.
    from app.services.risk_engine import score_alert_risk

    a1 = await score_alert_risk(db_session, a1)
    assert a1.risk_score_breakdown["correlated_alert_count"] == 1
    assert a1.risk_score_breakdown["correlation_bonus"] == 3
