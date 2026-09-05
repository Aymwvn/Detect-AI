"""
Integration tests for POST/GET /alerts/{id}/feedback (app/api/alerts.py).
"""

import pytest

from app.db.models import AuditLog
from sqlalchemy import select


async def _create_alert(client) -> str:
    resp = await client.post(
        "/api/v1/alerts",
        json={
            "timestamp": "2026-08-26T10:31:19Z",
            "source": "feedback-test",
            "source_product": "generic_webhook",
        },
    )
    return resp.json()["alert_id"]


@pytest.mark.asyncio
async def test_submit_feedback_success(client):
    alert_id = await _create_alert(client)
    resp = await client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"analyst_id": "analyst-1", "label": "false_positive", "comment": "IT automation"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["label"] == "false_positive"
    assert body["alert_id"] == alert_id


@pytest.mark.asyncio
async def test_submit_feedback_invalid_label_rejected(client):
    alert_id = await _create_alert(client)
    resp = await client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"analyst_id": "analyst-1", "label": "definitely_not_a_real_label"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_submit_feedback_nonexistent_alert_404(client):
    resp = await client.post(
        "/api/v1/alerts/does-not-exist/feedback",
        json={"analyst_id": "analyst-1", "label": "true_positive"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_feedback_returns_submitted_entries(client):
    alert_id = await _create_alert(client)
    await client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"analyst_id": "analyst-1", "label": "true_positive"},
    )
    await client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"analyst_id": "analyst-2", "label": "needs_investigation", "comment": "checking further"},
    )
    resp = await client.get(f"/api/v1/alerts/{alert_id}/feedback")
    assert resp.status_code == 200
    labels = {f["label"] for f in resp.json()}
    assert labels == {"true_positive", "needs_investigation"}


@pytest.mark.asyncio
async def test_list_feedback_empty_for_alert_with_none(client):
    alert_id = await _create_alert(client)
    resp = await client.get(f"/api/v1/alerts/{alert_id}/feedback")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_feedback_nonexistent_alert_404(client):
    resp = await client.get("/api/v1/alerts/does-not-exist/feedback")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_feedback_submission_writes_audit_log(client, db_session):
    alert_id = await _create_alert(client)
    await client.post(
        f"/api/v1/alerts/{alert_id}/feedback",
        json={"analyst_id": "analyst-1", "label": "confirmed_incident"},
    )
    result = await db_session.execute(
        select(AuditLog).where(AuditLog.object_id == alert_id, AuditLog.action == "feedback_submitted")
    )
    entry = result.scalar_one()
    assert entry.actor == "analyst-1"
    assert entry.details["label"] == "confirmed_incident"
