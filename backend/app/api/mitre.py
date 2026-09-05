"""MITRE ATT&CK API router (architecture doc section 19)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AIAnalysis
from app.db.models import Alert as AlertModel
from app.db.models import MitreTechnique
from app.db.session import get_db
from app.services.mitre.mapper import map_alert_to_mitre
from app.services.mitre.sync import sync_mitre_techniques

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/techniques")
async def list_techniques(
    limit: int = 100, offset: int = 0, tactic: str | None = None, db: AsyncSession = Depends(get_db)
) -> list[dict]:
    query = select(MitreTechnique)
    if tactic:
        query = query.where(MitreTechnique.tactic == tactic)
    query = query.order_by(MitreTechnique.technique_id).offset(offset).limit(limit)
    result = await db.execute(query)
    return [
        {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic, "url": t.url}
        for t in result.scalars().all()
    ]


@router.get("/techniques/{technique_id}")
async def get_technique(technique_id: str, db: AsyncSession = Depends(get_db)) -> dict:
    technique = await db.get(MitreTechnique, technique_id)
    if technique is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Technique not found")
    return {
        "technique_id": technique.technique_id,
        "name": technique.name,
        "tactic": technique.tactic,
        "description": technique.description,
        "url": technique.url,
    }


@router.post("/sync")
async def trigger_sync(db: AsyncSession = Depends(get_db)) -> dict:
    """Fetches the latest official MITRE ATT&CK data and upserts it into
    the local reference table. Safe to call repeatedly (idempotent
    upsert) — intended to be run periodically (e.g. a scheduled job), not
    on every request."""
    try:
        count = await sync_mitre_techniques(db)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"MITRE sync failed: {exc}"
        )
    return {"synced_technique_count": count}


@router.get("/alerts/{alert_id}/mapping")
async def get_alert_mitre_mapping(alert_id: str, db: AsyncSession = Depends(get_db)) -> dict:
    """The validated, enriched MITRE mapping for one alert — combines the
    source's own claim and the most recent AI analysis's claim (if any),
    cross-checked against the synced reference data."""
    alert = await db.get(AlertModel, alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    result = await db.execute(
        select(AIAnalysis)
        .where(AIAnalysis.alert_id == alert_id, AIAnalysis.validation_status == "valid")
        .order_by(AIAnalysis.created_at.desc())
        .limit(1)
    )
    latest_analysis = result.scalar_one_or_none()

    return await map_alert_to_mitre(db, alert, latest_analysis)
