"""Integration tests for app/api/mitre.py"""

import pytest

from app.db.models import MitreTechnique


async def _seed_technique(db_session, technique_id="T1059.001", name="PowerShell", tactic="Execution"):
    technique = MitreTechnique(technique_id=technique_id, name=name, tactic=tactic, url="https://example.com")
    db_session.add(technique)
    await db_session.commit()
    return technique


@pytest.mark.asyncio
async def test_list_techniques(client, db_session):
    await _seed_technique(db_session)
    resp = await client.get("/api/v1/mitre/techniques")
    assert resp.status_code == 200
    assert any(t["technique_id"] == "T1059.001" for t in resp.json())


@pytest.mark.asyncio
async def test_list_techniques_filtered_by_tactic(client, db_session):
    await _seed_technique(db_session, technique_id="T1059.001", tactic="Execution")
    await _seed_technique(db_session, technique_id="T1566", name="Phishing", tactic="Initial Access")

    resp = await client.get("/api/v1/mitre/techniques", params={"tactic": "Execution"})
    ids = {t["technique_id"] for t in resp.json()}
    assert ids == {"T1059.001"}


@pytest.mark.asyncio
async def test_get_technique_by_id(client, db_session):
    await _seed_technique(db_session)
    resp = await client.get("/api/v1/mitre/techniques/T1059.001")
    assert resp.status_code == 200
    assert resp.json()["name"] == "PowerShell"


@pytest.mark.asyncio
async def test_get_nonexistent_technique_404(client):
    resp = await client.get("/api/v1/mitre/techniques/T0000")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_alert_mitre_mapping_endpoint(client, db_session):
    await _seed_technique(db_session)
    create_resp = await client.post(
        "/api/v1/alerts",
        json={
            "timestamp": "2026-08-26T10:31:19Z",
            "source": "mitre-test",
            "source_product": "generic_webhook",
            "existing_mitre_attack_mapping": [{"technique_id": "T1059.001", "technique_name": "PowerShell"}],
        },
    )
    alert_id = create_resp.json()["alert_id"]

    resp = await client.get(f"/api/v1/mitre/alerts/{alert_id}/mapping")
    assert resp.status_code == 200
    body = resp.json()
    assert body["techniques"][0]["technique_id"] == "T1059.001"
    assert body["invalid_technique_ids"] == []


@pytest.mark.asyncio
async def test_alert_mitre_mapping_nonexistent_alert_404(client):
    resp = await client.get("/api/v1/mitre/alerts/does-not-exist/mapping")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sync_requires_authentication(client):
    resp = await client.post("/api/v1/mitre/sync")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_sync_rejects_non_admin_role(client, auth_headers):
    headers = await auth_headers("analyst")
    resp = await client.post("/api/v1/mitre/sync", headers=headers)
    assert resp.status_code == 403
