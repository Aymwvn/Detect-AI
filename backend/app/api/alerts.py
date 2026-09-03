"""
Alerts API router.

Endpoints match architecture doc section 19. Backed by real PostgreSQL
persistence via the ingestion service (app/services/ingestion.py) as of
Phase 10 — the Phase 3 in-memory placeholder store is gone.

This POST /alerts endpoint expects an already-normalized CommonAlertSchema
body — it's for trusted callers (internal tooling, a connector's own poll
loop, tests) that have already run normalize_event() themselves. Untrusted
raw JSON from an external webhook sender goes through POST /webhooks/{id}
instead (app/api/webhooks.py, Phase 10), which verifies an HMAC signature
and normalizes via GenericWebhookConnector before it ever reaches this
ingestion path.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Alert as AlertModel
from app.db.session import get_db
from app.schemas import CommonAlertSchema
from app.services.ingestion import alert_model_to_schema, ingest_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("", response_model=CommonAlertSchema, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert: CommonAlertSchema, db: AsyncSession = Depends(get_db)
) -> CommonAlertSchema:
    db_alert = await ingest_alert(db, alert)
    return alert_model_to_schema(db_alert)


@router.get("", response_model=list[CommonAlertSchema])
async def list_alerts(
    limit: int = 50, offset: int = 0, db: AsyncSession = Depends(get_db)
) -> list[CommonAlertSchema]:
    result = await db.execute(
        select(AlertModel).order_by(AlertModel.ingested_at.desc()).offset(offset).limit(limit)
    )
    return [alert_model_to_schema(a) for a in result.scalars().all()]


@router.get("/{alert_id}", response_model=CommonAlertSchema)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)) -> CommonAlertSchema:
    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    db_alert = result.scalar_one_or_none()
    if db_alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert_model_to_schema(db_alert)


@router.post("/{alert_id}/analyze")
async def analyze_alert(alert_id: str, db: AsyncSession = Depends(get_db)) -> dict:
    """Trigger AI/rule-based analysis for an alert. Wired up in Phase 12-14."""
    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Analysis engine not yet implemented (Phase 12-14).",
    )


@router.post("/{alert_id}/feedback")
async def submit_feedback(alert_id: str, db: AsyncSession = Depends(get_db)) -> dict:
    """Analyst TP/FP/benign labeling. Wired up in Phase 17."""
    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Feedback loop not yet implemented (Phase 17).",
    )
