"""
Deduplication engine (architecture doc section 8).

Groups alerts that represent the SAME underlying event into one
dedup_group_id — e.g. 500 near-identical detections of one process
execution shouldn't read as 500 separate incidents to an analyst.

Design: an exact-match signature built from entity keys (hostname,
username, source_ip, destination_ip, domain, file_hash) plus rule_id,
matched against other alerts within a configurable time window. This is
deliberately NOT fuzzy/ML-based matching — it's a documented simplification
appropriate for an MVP: two alerts must share every populated key exactly
to be considered duplicates. A future pass could relax this (e.g. partial
key overlap with a similarity threshold) without changing the public
function signatures here.

An alert with no populated entity keys at all can't be safely deduplicated
(there's nothing to match on) and always becomes its own group leader.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert

DEFAULT_DEDUP_WINDOW_MINUTES = 5

# Order matters for signature stability, but sorted() in compute_signature
# makes the actual key order irrelevant to the output hash.
_SIGNATURE_FIELDS = ["hostname", "username", "source_ip", "destination_ip", "domain", "file_hash", "rule_id"]


def compute_signature(alert: Alert) -> Optional[str]:
    """Returns a stable hash of this alert's populated entity keys, or
    None if the alert has no usable keys at all (nothing to dedup against)."""
    present = {field: getattr(alert, field) for field in _SIGNATURE_FIELDS if getattr(alert, field)}
    if not present:
        return None
    signature_input = "|".join(f"{k}={v}" for k, v in sorted(present.items()))
    return hashlib.sha256(signature_input.encode()).hexdigest()


async def deduplicate_alert(
    db: AsyncSession, alert: Alert, window_minutes: int = DEFAULT_DEDUP_WINDOW_MINUTES
) -> Alert:
    """Computes and stores this alert's dedup signature, then either joins
    an existing dedup group (a prior alert with the same signature within
    the window) or becomes a new group's leader. Idempotent to call again
    on the same alert — it will simply recompute and re-match."""
    signature = compute_signature(alert)
    alert.dedup_signature = signature

    if signature is None:
        alert.dedup_group_id = alert.alert_id
    else:
        window_start = alert.timestamp - timedelta(minutes=window_minutes)
        result = await db.execute(
            select(Alert)
            .where(
                Alert.dedup_signature == signature,
                Alert.alert_id != alert.alert_id,
                Alert.timestamp >= window_start,
                Alert.timestamp <= alert.timestamp,
            )
            .order_by(Alert.timestamp.asc())
            .limit(1)
        )
        match = result.scalar_one_or_none()
        alert.dedup_group_id = (match.dedup_group_id or match.alert_id) if match else alert.alert_id

    await db.commit()
    await db.refresh(alert)
    return alert
