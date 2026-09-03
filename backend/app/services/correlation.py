"""
Correlation engine (architecture doc section 9).

Groups DIFFERENT alerts that likely represent stages of the SAME attack
chain into one Incident — e.g. a phishing alert, a PowerShell execution
alert, and a persistence alert on the same host within a few hours should
read as one incident, not three unrelated ones.

Design: unlike deduplication's exact-signature match, correlation matches
on ANY shared entity value (hostname OR username OR source_ip OR
destination_ip OR domain OR file_hash) within a wider window — this is
intentionally looser than dedup, since attack-chain stages often share
only a host or user, not every field. Same documented simplification
caveat as deduplication.py: exact string equality on entity values, no
fuzzy matching, no confidence scoring on the correlation itself (that
happens downstream in risk scoring / AI analysis).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert, Incident

DEFAULT_CORRELATION_WINDOW_HOURS = 24

_ENTITY_FIELDS = ["hostname", "username", "source_ip", "destination_ip", "domain", "file_hash"]


def entity_conditions(alert: Alert) -> list:
    """SQLAlchemy column-equality conditions for every entity field this
    alert has populated. Returns [] if the alert has no entity context."""
    return [
        getattr(Alert, field) == getattr(alert, field)
        for field in _ENTITY_FIELDS
        if getattr(alert, field)
    ]


async def correlate_alert(
    db: AsyncSession, alert: Alert, window_hours: int = DEFAULT_CORRELATION_WINDOW_HOURS
) -> Alert:
    """Attaches this alert to an existing incident if it shares an entity
    with an already-incident-linked alert in the window; otherwise, if it
    shares an entity with an incident-less sibling alert, creates a new
    incident joining both. An alert with no entity context, or no matches
    at all, is left without an incident_id (it may get one later when a
    correlated alert arrives)."""
    conditions = entity_conditions(alert)
    if not conditions:
        return alert

    window_start = alert.timestamp - timedelta(hours=window_hours)

    # Case 1: a matching alert already belongs to an incident -> join it.
    result = await db.execute(
        select(Alert)
        .where(
            Alert.alert_id != alert.alert_id,
            Alert.timestamp >= window_start,
            Alert.timestamp <= alert.timestamp,
            Alert.incident_id.isnot(None),
            or_(*conditions),
        )
        .order_by(Alert.timestamp.asc())
        .limit(1)
    )
    already_incident = result.scalar_one_or_none()
    if already_incident is not None:
        alert.incident_id = already_incident.incident_id
        await db.commit()
        await db.refresh(alert)
        return alert

    # Case 2: a matching sibling alert exists but has no incident yet ->
    # this is the first correlation between them, so create one incident
    # covering both.
    result = await db.execute(
        select(Alert)
        .where(
            Alert.alert_id != alert.alert_id,
            Alert.timestamp >= window_start,
            Alert.timestamp <= alert.timestamp,
            Alert.incident_id.is_(None),
            or_(*conditions),
        )
        .order_by(Alert.timestamp.asc())
        .limit(1)
    )
    sibling = result.scalar_one_or_none()
    if sibling is not None:
        incident = Incident(
            title=f"Correlated activity: {alert.hostname or alert.username or alert.rule_name or 'unnamed asset'}"
        )
        db.add(incident)
        await db.flush()  # get incident.id without a separate round trip
        alert.incident_id = incident.id
        sibling.incident_id = incident.id
        await db.commit()
        await db.refresh(alert)
        return alert

    # Case 3: no correlation found — leave uncorrelated for now.
    return alert
