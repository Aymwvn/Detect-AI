"""
Password hashing and JWT handling.

Passwords are hashed with bcrypt (via passlib) — never stored or logged
in plaintext. JWTs are signed with Settings.secret_key (HS256) and carry a
short expiry (Settings.access_token_expire_minutes); there is no refresh
token mechanism in this MVP — a client must re-authenticate after expiry.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from app.core.config import Settings


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))


def create_access_token(subject: str, role: str, settings: Settings) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_expire_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


class TokenError(Exception):
    """Raised for any invalid, expired, or malformed token."""


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
