"""Tests for app/core/security.py and app/core/deps.py"""

import time

import pytest
from fastapi import HTTPException

from app.core.config import Settings
from app.core.deps import get_current_user, require_role
from app.core.security import TokenError, create_access_token, decode_access_token, hash_password, verify_password


def _settings(**overrides) -> Settings:
    overrides.setdefault("secret_key", "test-secret-key")
    return Settings(**overrides)


# --- password hashing -------------------------------------------------

def test_hash_password_produces_different_hash_each_time():
    """bcrypt salts automatically — same password, different hash."""
    h1 = hash_password("correct horse battery staple")
    h2 = hash_password("correct horse battery staple")
    assert h1 != h2


def test_verify_password_correct():
    hashed = hash_password("my-password-123")
    assert verify_password("my-password-123", hashed) is True


def test_verify_password_incorrect():
    hashed = hash_password("my-password-123")
    assert verify_password("wrong-password", hashed) is False


def test_hashed_password_is_not_plaintext():
    hashed = hash_password("my-password-123")
    assert "my-password-123" not in hashed


# --- JWT -------------------------------------------------

def test_create_and_decode_token_roundtrip():
    settings = _settings()
    token = create_access_token(subject="alice", role="analyst", settings=settings)
    payload = decode_access_token(token, settings)
    assert payload["sub"] == "alice"
    assert payload["role"] == "analyst"


def test_decode_token_wrong_secret_raises():
    settings1 = _settings(secret_key="secret-one")
    settings2 = _settings(secret_key="secret-two")
    token = create_access_token(subject="alice", role="analyst", settings=settings1)
    with pytest.raises(TokenError):
        decode_access_token(token, settings2)


def test_decode_garbage_token_raises():
    with pytest.raises(TokenError):
        decode_access_token("not.a.real.jwt", _settings())


def test_expired_token_raises():
    settings = _settings(access_token_expire_minutes=0)
    token = create_access_token(subject="alice", role="viewer", settings=settings)
    time.sleep(1.1)
    with pytest.raises(TokenError):
        decode_access_token(token, settings)


# --- get_current_user / require_role -------------------------------------------------

@pytest.mark.asyncio
async def test_get_current_user_no_credentials_raises_401():
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials=None, settings=_settings())
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_invalid_token_raises_401():
    from fastapi.security import HTTPAuthorizationCredentials

    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="garbage-token")
    with pytest.raises(HTTPException) as exc_info:
        await get_current_user(credentials=creds, settings=_settings())
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_require_role_allows_matching_role():
    from app.core.deps import CurrentUser

    dependency = require_role("analyst", "admin")
    user = CurrentUser(username="alice", role="analyst")
    result = await dependency(current_user=user)
    assert result is user


@pytest.mark.asyncio
async def test_require_role_rejects_non_matching_role():
    from app.core.deps import CurrentUser

    dependency = require_role("admin")
    user = CurrentUser(username="alice", role="viewer")
    with pytest.raises(HTTPException) as exc_info:
        await dependency(current_user=user)
    assert exc_info.value.status_code == 403
