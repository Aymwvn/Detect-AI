"""
Rule-based risk engine (architecture doc section 17).

Runs independent of any LLM — this is what keeps the pipeline "fully
functional with AI_PROVIDER=none" (architecture doc section 13). AI
analysis (Phase 14) can add its own risk assessment on top, but this
score always exists for every ingested alert.

Every contributing factor is recorded in `risk_score_breakdown` so an
analyst (or this codebase's own tests) can see exactly why a score was
assigned — never a bare number with no explanation, per architecture doc
section 17 ("show the analyst exactly why an alert received its score").
"""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert, Entity

SEVERITY_BASE_SCORE = {
    "informational": 5,
    "low": 20,
    "medium": 40,
    "high": 65,
    "critical": 85,
    "unknown": 30,
}

CRITICALITY_BONUS = {"low": 0, "medium": 5, "high": 10, "critical": 15}

CORRELATION_BONUS_PER_ALERT = 3
CORRELATION_BONUS_CAP = 15
MITRE_MAPPING_BONUS = 10
USER_PRIVILEGE_BONUS = 10

MAX_SCORE = 100


def priority_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


async def _count_correlated_alerts(db: AsyncSession, alert: Alert) -> int:
    """Number of OTHER alerts in the same incident (0 if uncorrelated)."""
    if not alert.incident_id:
        return 0
    result = await db.execute(
        select(func.count()).select_from(Alert).where(Alert.incident_id == alert.incident_id)
    )
    total = result.scalar_one()
    return max(total - 1, 0)  # exclude self


async def _asset_criticality_bonus(db: AsyncSession, hostname: str | None) -> int:
    if not hostname:
        return 0
    result = await db.execute(select(Entity).where(Entity.entity_type == "host", Entity.value == hostname))
    entity = result.scalar_one_or_none()
    if entity is None or not entity.criticality:
        return 0
    return CRITICALITY_BONUS.get(entity.criticality, 0)


async def _user_privilege_bonus(db: AsyncSession, username: str | None) -> int:
    if not username:
        return 0
    result = await db.execute(select(Entity).where(Entity.entity_type == "user", Entity.value == username))
    entity = result.scalar_one_or_none()
    if entity is None or not entity.privilege_level:
        return 0
    return USER_PRIVILEGE_BONUS


async def score_alert_risk(db: AsyncSession, alert: Alert) -> Alert:
    """Computes and persists alert.risk_score, risk_score_breakdown, and
    investigation_priority. Safe to call multiple times (e.g. after
    correlation changes the incident this alert belongs to) — it always
    recomputes from current state rather than accumulating."""
    breakdown: dict = {}

    severity_base = SEVERITY_BASE_SCORE.get(alert.severity, SEVERITY_BASE_SCORE["unknown"])
    breakdown["severity_base"] = severity_base

    correlated_count = await _count_correlated_alerts(db, alert)
    correlation_bonus = min(correlated_count * CORRELATION_BONUS_PER_ALERT, CORRELATION_BONUS_CAP)
    breakdown["correlation_bonus"] = correlation_bonus
    breakdown["correlated_alert_count"] = correlated_count

    mitre_bonus = MITRE_MAPPING_BONUS if alert.existing_mitre_attack_mapping else 0
    breakdown["mitre_mapping_bonus"] = mitre_bonus

    criticality_bonus = await _asset_criticality_bonus(db, alert.hostname)
    breakdown["asset_criticality_bonus"] = criticality_bonus

    privilege_bonus = await _user_privilege_bonus(db, alert.username)
    breakdown["user_privilege_bonus"] = privilege_bonus

    total = min(
        severity_base + correlation_bonus + mitre_bonus + criticality_bonus + privilege_bonus,
        MAX_SCORE,
    )
    breakdown["total"] = total

    alert.risk_score = total
    alert.risk_score_breakdown = breakdown
    alert.investigation_priority = priority_band(total)

    await db.commit()
    await db.refresh(alert)
    return alert
