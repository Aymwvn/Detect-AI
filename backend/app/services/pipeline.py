"""
Post-ingestion pipeline orchestrator.

Matches the architecture doc's data flow (section 6): every ingested alert
runs through deduplication -> correlation -> rule-based risk scoring
automatically, with zero LLM involvement. AI analysis (Phase 14) is
deliberately NOT part of this automatic pipeline — it's triggered
on-demand via POST /alerts/{id}/analyze, matching the API spec (section
19) and keeping expensive/optional LLM calls out of the hot ingestion path.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert
from app.services.correlation import correlate_alert
from app.services.deduplication import deduplicate_alert
from app.services.risk_engine import score_alert_risk


async def process_new_alert(db: AsyncSession, alert: Alert) -> Alert:
    """Runs the full automatic (non-AI) pipeline on a freshly ingested
    alert. Order matters: risk scoring reads alert.incident_id, so
    correlation must run first; dedup and correlation are independent of
    each other but dedup runs first since it's the cheaper, narrower check."""
    alert = await deduplicate_alert(db, alert)
    alert = await correlate_alert(db, alert)
    alert = await score_alert_risk(db, alert)
    return alert
