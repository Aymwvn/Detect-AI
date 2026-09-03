"""
Webhook ingestion endpoint.

The real entry point for GenericWebhookConnector (connectors/generic.py,
Phase 9). Every inbound request here is untrusted per architecture doc
section 14: the raw request body is read and its HMAC signature verified
against the configured connector's shared_secret BEFORE the JSON is even
parsed — a request with no valid signature never reaches normalize_event()
or the database, regardless of what its body contains.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Connector as ConnectorModel
from app.db.session import get_db
from app.services.ingestion import ingest_alert
from connectors.generic import GenericWebhookConnector

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


@router.post("/{connector_id}", status_code=status.HTTP_201_CREATED)
async def receive_webhook_alert(
    connector_id: str,
    request: Request,
    x_detectai_signature: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(select(ConnectorModel).where(ConnectorModel.id == connector_id))
    connector_row = result.scalar_one_or_none()
    if connector_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")

    if connector_row.source_product != "generic_webhook":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This connector is not configured as a generic_webhook source",
        )

    # Signature is checked against the RAW bytes, before any parsing —
    # parsing first and re-serializing to check the signature would let a
    # request with a semantically-identical-but-differently-formatted body
    # slip past a signature computed over the original bytes.
    body_bytes = await request.body()

    connector = GenericWebhookConnector(
        connector_id=connector_row.id,
        name=connector_row.name,
        config=connector_row.config,
    )

    if not connector.verify_signature(body_bytes, x_detectai_signature):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing signature")

    try:
        raw = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Request body is not valid JSON")

    if not isinstance(raw, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Request body must be a JSON object"
        )

    normalized = connector.normalize_event(raw)
    db_alert = await ingest_alert(db, normalized, connector_id=connector_row.id)

    return {"alert_id": db_alert.alert_id, "status": "ingested"}
