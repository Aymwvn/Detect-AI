"""
Alerts API router.

Endpoints match architecture doc section 19. Bodies are stubbed with
in-memory placeholders for now — real persistence lands in Phase 4
(PostgreSQL) and the ingestion/dedup/correlation/risk logic lands in
Phases 10-12. This router exists now so the API surface, request/response
schemas, and auth/RBAC wiring are locked in early and don't get
retrofitted awkwardly later.
"""

from fastapi import APIRouter, HTTPException, status

from app.schemas import CommonAlertSchema

router = APIRouter(prefix="/alerts", tags=["alerts"])

# TEMPORARY in-memory store — replaced by PostgreSQL in Phase 4.
_ALERTS_STORE: dict[str, CommonAlertSchema] = {}


@router.post("", response_model=CommonAlertSchema, status_code=status.HTTP_201_CREATED)
async def create_alert(alert: CommonAlertSchema) -> CommonAlertSchema:
    """Ingest a single normalized alert.

    NOTE: real connectors don't call this directly with pre-normalized data —
    they call it via the ingestion service after running their own
    normalize_event(). This endpoint doubles as the generic webhook/JSON
    connector's entry point (Phase 9).
    """
    _ALERTS_STORE[alert.alert_id] = alert
    return alert


@router.get("", response_model=list[CommonAlertSchema])
async def list_alerts(limit: int = 50, offset: int = 0) -> list[CommonAlertSchema]:
    values = list(_ALERTS_STORE.values())
    return values[offset : offset + limit]


@router.get("/{alert_id}", response_model=CommonAlertSchema)
async def get_alert(alert_id: str) -> CommonAlertSchema:
    alert = _ALERTS_STORE.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert


@router.post("/{alert_id}/analyze")
async def analyze_alert(alert_id: str) -> dict:
    """Trigger AI/rule-based analysis for an alert. Wired up in Phase 12-14."""
    if alert_id not in _ALERTS_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Analysis engine not yet implemented (Phase 12-14).",
    )


@router.post("/{alert_id}/feedback")
async def submit_feedback(alert_id: str) -> dict:
    """Analyst TP/FP/benign labeling. Wired up in Phase 17."""
    if alert_id not in _ALERTS_STORE:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Feedback loop not yet implemented (Phase 17).",
    )
