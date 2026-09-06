"""
Integration tests for the alerts API (app/api/alerts.py), using a real
ASGI HTTP client against an in-memory SQLite DB (see tests/conftest.py).
Supersedes the manual TestClient smoke-test from Phase 3 now that this
router is backed by real persistence instead of an in-memory dict.
"""

import pytest


@pytest.mark.asyncio
async def test_create_and_get_alert(client):
    payload = {
        "timestamp": "2026-08-26T10:31:19Z",
        "source": "api-test-source",
        "source_product": "generic_webhook",
        "severity": "high",
        "hostname": "WIN10-TEST",
    }
    resp = await client.post("/api/v1/alerts", json=payload)
    assert resp.status_code == 201
    alert_id = resp.json()["alert_id"]

    resp2 = await client.get(f"/api/v1/alerts/{alert_id}")
    assert resp2.status_code == 200
    assert resp2.json()["hostname"] == "WIN10-TEST"
    assert resp2.json()["severity"] == "high"


@pytest.mark.asyncio
async def test_list_alerts(client):
    for i in range(3):
        await client.post(
            "/api/v1/alerts",
            json={
                "timestamp": "2026-08-26T10:31:19Z",
                "source": f"src-{i}",
                "source_product": "generic_webhook",
            },
        )
    resp = await client.get("/api/v1/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 3


@pytest.mark.asyncio
async def test_get_nonexistent_alert_404(client):
    resp = await client.get("/api/v1/alerts/does-not-exist")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyze_with_no_ai_provider_returns_rule_based_score_only(client, auth_headers):
    """Default test settings have AI_PROVIDER=none, so /analyze should
    return the rule-based risk score (computed automatically on ingest)
    without attempting any AI call."""
    resp = await client.post(
        "/api/v1/alerts",
        json={
            "timestamp": "2026-08-26T10:31:19Z",
            "source": "src-analyze",
            "source_product": "generic_webhook",
            "severity": "high",
        },
    )
    alert_id = resp.json()["alert_id"]
    headers = await auth_headers("analyst")
    resp2 = await client.post(f"/api/v1/alerts/{alert_id}/analyze", headers=headers)
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["ai_analysis"] is None
    assert body["risk_score"] is not None
    assert body["risk_score_breakdown"] is not None


@pytest.mark.asyncio
async def test_analyze_404_for_nonexistent_alert(client, auth_headers):
    headers = await auth_headers("analyst")
    resp = await client.post("/api/v1/alerts/does-not-exist/analyze", headers=headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_analyze_requires_authentication(client):
    resp = await client.post(
        "/api/v1/alerts",
        json={"timestamp": "2026-08-26T10:31:19Z", "source": "s", "source_product": "generic_webhook"},
    )
    alert_id = resp.json()["alert_id"]
    resp2 = await client.post(f"/api/v1/alerts/{alert_id}/analyze")
    assert resp2.status_code == 401


@pytest.mark.asyncio
async def test_analyze_rejects_viewer_role(client, auth_headers):
    """A viewer (read-only role) must not be able to trigger analysis —
    only analyst/admin."""
    resp = await client.post(
        "/api/v1/alerts",
        json={"timestamp": "2026-08-26T10:31:19Z", "source": "s", "source_product": "generic_webhook"},
    )
    alert_id = resp.json()["alert_id"]
    headers = await auth_headers("viewer")
    resp2 = await client.post(f"/api/v1/alerts/{alert_id}/analyze", headers=headers)
    assert resp2.status_code == 403


@pytest.mark.asyncio
async def test_duplicate_external_alert_id_returns_same_alert(client):
    payload = {
        "timestamp": "2026-08-26T10:31:19Z",
        "source": "dedup-source",
        "source_product": "generic_webhook",
        "external_alert_id": "dup-external-1",
    }
    resp1 = await client.post("/api/v1/alerts", json=payload)
    resp2 = await client.post("/api/v1/alerts", json=payload)
    assert resp1.json()["alert_id"] == resp2.json()["alert_id"]


@pytest.mark.asyncio
async def test_created_alert_response_includes_risk_score(client):
    """Regression test: risk_score/investigation_priority must be present
    in the API response, not just in the DB — this was a real gap caught
    while building the frontend (Phase 16)."""
    resp = await client.post(
        "/api/v1/alerts",
        json={
            "timestamp": "2026-08-26T10:31:19Z",
            "source": "risk-visibility-test",
            "source_product": "generic_webhook",
            "severity": "critical",
        },
    )
    body = resp.json()
    assert body["risk_score"] is not None
    assert body["risk_score_breakdown"] is not None
    assert body["investigation_priority"] is not None
