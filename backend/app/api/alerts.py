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
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.models import AnalystFeedback, AuditLog
from app.db.models import Alert as AlertModel
from app.db.session import get_db
from app.schemas import CommonAlertSchema
from app.services.ai.analysis import analyze_alert as run_ai_analysis
from app.services.ai.exceptions import LLMProviderError
from app.services.ai.factory import get_llm_provider
from app.services.ingestion import alert_model_to_schema, ingest_alert
from app.services.pipeline import process_new_alert

ALLOWED_FEEDBACK_LABELS = {
    "true_positive",
    "false_positive",
    "benign",
    "needs_investigation",
    "confirmed_incident",
}

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("", response_model=CommonAlertSchema, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert: CommonAlertSchema, db: AsyncSession = Depends(get_db)
) -> CommonAlertSchema:
    db_alert = await ingest_alert(db, alert)
    db_alert = await process_new_alert(db, db_alert)
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
    """Triggers AI analysis on demand — deliberately not run automatically
    on ingest (see app/services/pipeline.py), keeping the LLM call out of
    the hot ingestion path. Always returns the rule-based risk score at
    minimum, since that's computed automatically for every alert
    regardless of whether AI is configured (architecture doc section 13).
    """
    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    db_alert = result.scalar_one_or_none()
    if db_alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    settings = get_settings()
    provider = get_llm_provider(settings)

    if provider is None:
        return {
            "alert_id": alert_id,
            "ai_analysis": None,
            "message": "AI_PROVIDER=none — rule-based risk score only.",
            "risk_score": db_alert.risk_score,
            "risk_score_breakdown": db_alert.risk_score_breakdown,
            "investigation_priority": db_alert.investigation_priority,
        }

    try:
        analysis = await run_ai_analysis(db, db_alert, provider)
    except LLMProviderError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"AI provider request failed: {exc}"
        )

    return {
        "alert_id": alert_id,
        "ai_analysis_id": analysis.id,
        "classification": analysis.classification,
        "risk_score": analysis.risk_score,
        "confidence": analysis.confidence,
        "investigation_priority": analysis.investigation_priority,
        "validation_status": analysis.validation_status,
        "rule_based_risk_score": db_alert.risk_score,
    }


class FeedbackSubmission(BaseModel):
    analyst_id: str
    label: str = Field(description=f"One of: {', '.join(sorted(ALLOWED_FEEDBACK_LABELS))}")
    comment: str | None = None


@router.post("/{alert_id}/feedback", status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    alert_id: str, submission: FeedbackSubmission, db: AsyncSession = Depends(get_db)
) -> dict:
    """Analyst TP/FP/benign labeling (architecture doc section 12).
    Stored for future evaluation/fine-tuning pipelines — NEVER used to
    automatically retrain or adjust anything in this codebase. An audit
    log entry is written alongside every submission so feedback history
    is independently verifiable, not just trusted from the feedback table
    itself."""
    if submission.label not in ALLOWED_FEEDBACK_LABELS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"label must be one of: {', '.join(sorted(ALLOWED_FEEDBACK_LABELS))}",
        )

    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    feedback = AnalystFeedback(
        alert_id=alert_id,
        analyst_id=submission.analyst_id,
        label=submission.label,
        comment=submission.comment,
    )
    db.add(feedback)

    db.add(
        AuditLog(
            actor=submission.analyst_id,
            action="feedback_submitted",
            object_type="alert",
            object_id=alert_id,
            details={"label": submission.label},
        )
    )

    await db.commit()
    await db.refresh(feedback)

    return {
        "feedback_id": feedback.id,
        "alert_id": alert_id,
        "label": feedback.label,
        "created_at": feedback.created_at.isoformat(),
    }


@router.get("/{alert_id}/feedback")
async def list_feedback(alert_id: str, db: AsyncSession = Depends(get_db)) -> list[dict]:
    """Feedback history for an alert — shown on the Investigation page so
    an analyst can see prior labels before adding their own."""
    result = await db.execute(select(AlertModel).where(AlertModel.alert_id == alert_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    result = await db.execute(
        select(AnalystFeedback)
        .where(AnalystFeedback.alert_id == alert_id)
        .order_by(AnalystFeedback.created_at.desc())
    )
    return [
        {
            "feedback_id": f.id,
            "analyst_id": f.analyst_id,
            "label": f.label,
            "comment": f.comment,
            "created_at": f.created_at.isoformat(),
        }
        for f in result.scalars().all()
    ]
