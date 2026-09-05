"""
DetectAI's own MITRE mapper (architecture doc section 10).

Distinct from the *vendor's own claim* (Alert.existing_mitre_attack_mapping,
set by connectors straight from source data — see connectors/elastic.py
and wazuh.py) and from the *AI's evidence-reconciled claim*
(AIAnalysis.mitre_techniques, already stripped of unsupported evidence by
Phase 14). This module is the final cross-check layer: it takes candidate
technique IDs from either or both of those sources and validates them
against the official MITRE reference data synced by sync.py. A technique
ID that doesn't exist in the real ATT&CK framework — a typo, a
hallucinated ID from a confused model, a vendor's outdated mapping — is
never silently attached to an alert or incident; it's reported separately
as invalid so the discrepancy is visible, not hidden.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AIAnalysis, Alert, MitreTechnique


async def validate_technique_ids(db: AsyncSession, technique_ids: list[str]) -> tuple[list[str], list[str]]:
    """Splits technique_ids into (valid, invalid) based on what's actually
    in the synced MITRE reference table. Order-preserving, deduplicated."""
    if not technique_ids:
        return [], []

    unique_ids = list(dict.fromkeys(technique_ids))  # dedupe, preserve order
    result = await db.execute(
        select(MitreTechnique.technique_id).where(MitreTechnique.technique_id.in_(unique_ids))
    )
    known = {row[0] for row in result.all()}

    valid = [t for t in unique_ids if t in known]
    invalid = [t for t in unique_ids if t not in known]
    return valid, invalid


async def get_technique_details(db: AsyncSession, technique_ids: list[str]) -> list[MitreTechnique]:
    if not technique_ids:
        return []
    result = await db.execute(select(MitreTechnique).where(MitreTechnique.technique_id.in_(technique_ids)))
    by_id = {t.technique_id: t for t in result.scalars().all()}
    # preserve caller's ordering rather than whatever the DB returns
    return [by_id[tid] for tid in technique_ids if tid in by_id]


async def map_alert_to_mitre(db: AsyncSession, alert: Alert, ai_analysis: AIAnalysis | None = None) -> dict:
    """Combines the vendor's own MITRE claim and the AI's (already
    evidence-reconciled) claim into one validated, enriched result.
    Invalid IDs are reported, not dropped silently — a discrepancy here
    might mean the vendor's rule metadata is stale, or (if it came from
    the AI path) that reconciliation let through a technique ID that's
    syntactically evidence-backed but doesn't correspond to a real
    technique — worth an analyst's attention either way."""
    candidate_ids: list[str] = []

    for mapping in alert.existing_mitre_attack_mapping or []:
        tid = mapping.get("technique_id")
        if tid:
            candidate_ids.append(tid)

    if ai_analysis is not None:
        for mapping in ai_analysis.mitre_techniques or []:
            tid = mapping.get("technique_id")
            if tid:
                candidate_ids.append(tid)

    valid_ids, invalid_ids = await validate_technique_ids(db, candidate_ids)
    details = await get_technique_details(db, valid_ids)

    return {
        "techniques": [
            {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic, "url": t.url}
            for t in details
        ],
        "invalid_technique_ids": invalid_ids,
    }
