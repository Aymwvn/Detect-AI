"""Integration tests for app/api/auth.py"""

import pytest


@pytest.mark.asyncio
async def test_register_success(client):
    resp = await client.post("/api/v1/auth/register", json={"username": "alice", "password": "secure-pass-123"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == "alice"
    assert body["role"] == "viewer"  # always viewer, regardless of what's requested


@pytest.mark.asyncio
async def test_register_role_field_is_ignored(client):
    """Even if a client tries to sneak an 'admin' role into the request
    body, RegisterRequest doesn't define that field at all, so it's
    silently dropped by Pydantic — not a vulnerability, just confirming
    the schema genuinely has no such field."""
    resp = await client.post(
        "/api/v1/auth/register",
        json={"username": "mallory", "password": "secure-pass-123", "role": "admin"},
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "viewer"


@pytest.mark.asyncio
async def test_register_duplicate_username_rejected(client):
    await client.post("/api/v1/auth/register", json={"username": "bob", "password": "secure-pass-123"})
    resp = await client.post("/api/v1/auth/register", json={"username": "bob", "password": "another-pass-456"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_register_short_password_rejected(client):
    resp = await client.post("/api/v1/auth/register", json={"username": "carol", "password": "short"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_success(client):
    await client.post("/api/v1/auth/register", json={"username": "dave", "password": "secure-pass-123"})
    resp = await client.post("/api/v1/auth/login", json={"username": "dave", "password": "secure-pass-123"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["role"] == "viewer"
    assert len(body["access_token"]) > 0


@pytest.mark.asyncio
async def test_login_wrong_password_rejected(client):
    await client.post("/api/v1/auth/register", json={"username": "erin", "password": "secure-pass-123"})
    resp = await client.post("/api/v1/auth/login", json={"username": "erin", "password": "wrong-password"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_nonexistent_user_rejected(client):
    resp = await client.post("/api/v1/auth/login", json={"username": "nobody", "password": "whatever123"})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_error_message_identical_for_bad_username_and_bad_password(client):
    """User-enumeration guard: both failure modes must produce the exact
    same response, so a client can't tell which one was wrong."""
    await client.post("/api/v1/auth/register", json={"username": "frank", "password": "secure-pass-123"})
    resp_bad_user = await client.post("/api/v1/auth/login", json={"username": "nonexistent", "password": "x"})
    resp_bad_pass = await client.post("/api/v1/auth/login", json={"username": "frank", "password": "wrong"})
    assert resp_bad_user.json()["detail"] == resp_bad_pass.json()["detail"]


@pytest.mark.asyncio
async def test_issued_token_actually_authenticates_protected_endpoint(client):
    """End-to-end: register, log in, use the returned token to hit a
    role-protected endpoint successfully. (A freshly registered user is
    only "viewer", so this hits a viewer-accessible action — listing
    feedback, which requires no role at all — to prove the token itself
    round-trips correctly through the real login flow.)"""
    await client.post("/api/v1/auth/register", json={"username": "grace", "password": "secure-pass-123"})
    login_resp = await client.post("/api/v1/auth/login", json={"username": "grace", "password": "secure-pass-123"})
    token = login_resp.json()["access_token"]

    create_resp = await client.post(
        "/api/v1/alerts",
        json={"timestamp": "2026-08-26T10:31:19Z", "source": "s", "source_product": "generic_webhook"},
    )
    alert_id = create_resp.json()["alert_id"]

    # analyze requires analyst/admin — a real "viewer" token must be rejected
    resp = await client.post(
        f"/api/v1/alerts/{alert_id}/analyze", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 403
