"""
Alert ingestion service.

This is the single place a normalized CommonAlertSchema (produced by any
connector's normalize_event()) becomes a persisted Alert row, and the
single place a persisted Alert row is converted back into a
CommonAlertSchema for API responses. Nothing else in the codebase should
INSERT into the alerts table directly or hand-roll that conversion — this
is where future concerns (audit logging on ingest, metrics, idempotency)
have one place to live.

Idempotency note: this does lightweight duplicate prevention keyed on
(source, external_alert_id) — re-ingesting the same vendor alert (e.g. a
connector's poll window overlapping the previous one) returns the existing
row instead of creating a duplicate. This is NOT the fuzzy, multi-field
deduplication engine from architecture doc section 8 (Phase 11), which
groups alerts that are *different documents* representing the same
underlying event. This is strictly "don't insert the exact same vendor
alert twice."
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert
from app.schemas import CommonAlertSchema
from connectors.base import SIEMConnector

logger = logging.getLogger(__name__)


async def find_existing_alert(
    db: AsyncSession, source: str, external_alert_id: Optional[str]
) -> Optional[Alert]:
    if not external_alert_id:
        return None
    result = await db.execute(
        select(Alert).where(Alert.source == source, Alert.external_alert_id == external_alert_id)
    )
    return result.scalar_one_or_none()


def _schema_to_model_fields(alert: CommonAlertSchema) -> dict:
    """Field-for-field conversion from the Pydantic CAS to the SQLAlchemy
    Alert model's constructor kwargs. Deliberately explicit (not
    alert.model_dump() passed wholesale) so a future CAS field addition
    doesn't silently start writing into an Alert column that doesn't
    exist, or vice versa — this function is the one place that mapping is
    asserted, and it'll fail loudly (TypeError: unexpected kwarg) if the
    two schemas drift apart."""
    return dict(
        external_alert_id=alert.external_alert_id,
        timestamp=alert.timestamp,
        source=alert.source,
        source_product=alert.source_product,
        severity=alert.severity,
        rule_name=alert.rule_name,
        rule_id=alert.rule_id,
        description=alert.description,
        hostname=alert.hostname,
        username=alert.username,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        source_port=alert.source_port,
        destination_port=alert.destination_port,
        protocol=alert.protocol,
        process_name=alert.process_name,
        parent_process=alert.parent_process,
        command_line=alert.command_line,
        file_hash=alert.file_hash,
        file_name=alert.file_name,
        domain=alert.domain,
        url=alert.url,
        cloud_account=alert.cloud_account,
        authentication_context=(
            alert.authentication_context.model_dump() if alert.authentication_context else None
        ),
        raw_event=alert.raw_event,
        tags=alert.tags,
        existing_mitre_attack_mapping=[m.model_dump() for m in alert.existing_mitre_attack_mapping],
        status=alert.status,
    )


def alert_model_to_schema(db_alert: Alert) -> CommonAlertSchema:
    """The reverse conversion — persisted row back to the wire schema."""
    return CommonAlertSchema(
        alert_id=db_alert.alert_id,
        external_alert_id=db_alert.external_alert_id,
        timestamp=db_alert.timestamp,
        ingested_at=db_alert.ingested_at,
        source=db_alert.source,
        source_product=db_alert.source_product,
        severity=db_alert.severity,
        rule_name=db_alert.rule_name,
        rule_id=db_alert.rule_id,
        description=db_alert.description,
        hostname=db_alert.hostname,
        username=db_alert.username,
        source_ip=db_alert.source_ip,
        destination_ip=db_alert.destination_ip,
        source_port=db_alert.source_port,
        destination_port=db_alert.destination_port,
        protocol=db_alert.protocol,
        process_name=db_alert.process_name,
        parent_process=db_alert.parent_process,
        command_line=db_alert.command_line,
        file_hash=db_alert.file_hash,
        file_name=db_alert.file_name,
        domain=db_alert.domain,
        url=db_alert.url,
        cloud_account=db_alert.cloud_account,
        authentication_context=db_alert.authentication_context,
        raw_event=db_alert.raw_event,
        tags=db_alert.tags,
        existing_mitre_attack_mapping=db_alert.existing_mitre_attack_mapping,
        status=db_alert.status,
        dedup_group_id=db_alert.dedup_group_id,
        incident_id=db_alert.incident_id,
        risk_score=db_alert.risk_score,
        risk_score_breakdown=db_alert.risk_score_breakdown,
        investigation_priority=db_alert.investigation_priority,
    )


async def ingest_alert(
    db: AsyncSession,
    alert: CommonAlertSchema,
    connector_id: Optional[str] = None,
) -> Alert:
    """Persists one normalized alert. Idempotent on (source,
    external_alert_id) when that id is present; always inserts when it's
    absent (some sources — certain webhook senders in particular — never
    provide one)."""
    existing = await find_existing_alert(db, alert.source, alert.external_alert_id)
    if existing is not None:
        logger.info(
            "Skipping duplicate ingest: source=%s external_alert_id=%s (existing alert_id=%s)",
            alert.source,
            alert.external_alert_id,
            existing.alert_id,
        )
        return existing

    fields = _schema_to_model_fields(alert)
    db_alert = Alert(alert_id=alert.alert_id, connector_id=connector_id, **fields)
    db.add(db_alert)
    await db.commit()
    await db.refresh(db_alert)
    return db_alert


async def ingest_from_connector_poll(
    db: AsyncSession,
    connector: SIEMConnector,
    since: datetime,
    connector_id: Optional[str] = None,
) -> list[Alert]:
    """Runs one fetch_alerts() + normalize_event() + ingest_alert() pass
    for a pull-based connector. A single malformed raw alert must not
    abort the whole batch — it's logged and skipped, matching
    connectors/base.py's own error-isolation guidance (a connector's
    correctness should be independently verifiable; one bad document from
    a flaky source shouldn't take down an entire poll cycle)."""
    raw_alerts = connector.fetch_alerts(since)
    ingested: list[Alert] = []
    for raw in raw_alerts:
        try:
            normalized = connector.normalize_event(raw)
        except Exception:
            logger.exception(
                "Failed to normalize alert from connector '%s'; skipping.", connector.name
            )
            continue
        db_alert = await ingest_alert(db, normalized, connector_id=connector_id)
        ingested.append(db_alert)
    return ingested
