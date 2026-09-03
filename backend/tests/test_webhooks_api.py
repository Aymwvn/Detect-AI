"""
Integration tests for the webhook ingestion endpoint (app/api/webhooks.py).

Proves GenericWebhookConnector.verify_signature() (Phase 9, tested in
isolation in tests/test_generic_connectors.py) is actually enforced at the
HTTP layer, not just correct as a standalone function.
"""

import hashlib
import hmac

import pytest

from app.db.models import Connector


async def _make_webhook_connector_row(
    db_session, shared_secret: str = "wh-secret", source_product: str = "generic_webhook"
) -> Connector:
    connector = Connector(
        name="test-webhook",
        source_product=source_product,
        status="active",
        config={"shared_secret": shared_secret},
    )
    db_session.add(connector)
    await db_session.commit()
    await db_session.refresh(connector)
    return connector


def _sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
async def test_webhook_accepts_validly_signed_request(client, db_session):
    connector = await _make_webhook_connector_row(db_session)
    body = b'{"hostname": "WEBHOOK-HOST", "severity": "high"}'
    signature = _sign(body, "wh-secret")

    resp = await client.post(
        f"/api/v1/webhooks/{connector.id}",
        content=body,
        headers={"content-type": "application/json", "X-DetectAI-Signature": signature},
    )
    assert resp.status_code == 201
    alert_id = resp.json()["alert_id"]

    get_resp = await client.get(f"/api/v1/alerts/{alert_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["hostname"] == "WEBHOOK-HOST"
    assert get_resp.json()["severity"] == "high"


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_signature(client, db_session):
    connector = await _make_webhook_connector_row(db_session)
    body = b'{"hostname": "WEBHOOK-HOST"}'

    resp = await client.post(
        f"/api/v1/webhooks/{connector.id}",
        content=body,
        headers={"X-DetectAI-Signature": "wrong-signature"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_rejects_missing_signature(client, db_session):
    connector = await _make_webhook_connector_row(db_session)
    resp = await client.post(f"/api/v1/webhooks/{connector.id}", content=b'{"hostname": "x"}')
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_rejects_tampered_body_with_stale_signature(client, db_session):
    """The actual attack this whole mechanism exists to stop: a valid
    signature for one payload must not authenticate a *different* payload."""
    connector = await _make_webhook_connector_row(db_session)
    original_body = b'{"hostname": "WEBHOOK-HOST", "severity": "low"}'
    tampered_body = b'{"hostname": "WEBHOOK-HOST", "severity": "critical"}'
    signature = _sign(original_body, "wh-secret")

    resp = await client.post(
        f"/api/v1/webhooks/{connector.id}",
        content=tampered_body,
        headers={"X-DetectAI-Signature": signature},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_webhook_unknown_connector_404(client):
    resp = await client.post(
        "/api/v1/webhooks/does-not-exist",
        content=b"{}",
        headers={"X-DetectAI-Signature": "whatever"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_webhook_rejects_non_webhook_connector_type(client, db_session):
    connector = await _make_webhook_connector_row(db_session, source_product="elastic_security")
    resp = await client.post(
        f"/api/v1/webhooks/{connector.id}",
        content=b"{}",
        headers={"X-DetectAI-Signature": "whatever"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_rejects_invalid_json_body(client, db_session):
    connector = await _make_webhook_connector_row(db_session)
    body = b"not valid json {{{"
    signature = _sign(body, "wh-secret")

    resp = await client.post(
        f"/api/v1/webhooks/{connector.id}",
        content=body,
        headers={"X-DetectAI-Signature": signature},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_webhook_rejects_non_object_json_body(client, db_session):
    connector = await _make_webhook_connector_row(db_session)
    body = b"[1, 2, 3]"
    signature = _sign(body, "wh-secret")

    resp = await client.post(
        f"/api/v1/webhooks/{connector.id}",
        content=body,
        headers={"X-DetectAI-Signature": signature},
    )
    assert resp.status_code == 400
