"""
Auth dependencies: get_current_user extracts and validates the bearer
token; require_role(...) builds a dependency that additionally checks the
token's role claim against an allow-list.

Role hierarchy is NOT implicit here — "admin" does not automatically pass
a require_role(["analyst"]) check. Each protected endpoint lists every
role allowed to use it explicitly, which is more verbose but means the
access list for any endpoint is fully visible at the call site instead of
requiring the reader to know an unwritten hierarchy.
"""

from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings
from app.core.security import TokenError, decode_access_token

_bearer_scheme = HTTPBearer(auto_error=False)


class CurrentUser:
    def __init__(self, username: str, role: str):
        self.username = username
        self.role = role


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials, settings)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return CurrentUser(username=payload["sub"], role=payload["role"])


def require_role(*allowed_roles: str):
    """Returns a dependency that requires the current user's role to be in
    allowed_roles. Usage: Depends(require_role("analyst", "admin"))."""

    async def dependency(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of these roles: {', '.join(allowed_roles)}",
            )
        return current_user

    return dependency
