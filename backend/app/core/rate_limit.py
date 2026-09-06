"""
Rate limiting middleware (architecture doc section 14).

In-memory, per-process sliding window keyed by client IP. This is a
documented simplification appropriate for a single-instance MVP
deployment: state doesn't survive a restart and isn't shared across
multiple backend instances. A production multi-instance deployment should
back this with Redis (Settings.redis_url already exists for exactly this)
so limits are enforced consistently across instances — swapping the store
is a small, isolated change since all the counting logic lives in one
place (_RateLimiterState) behind a narrow interface.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class _RateLimiterState:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = limit_per_minute
        self._requests: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        window_start = now - 60.0
        bucket = self._requests[key]

        while bucket and bucket[0] < window_start:
            bucket.popleft()

        if len(bucket) >= self.limit_per_minute:
            return False

        bucket.append(now)
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, limit_per_minute: int = 120):
        super().__init__(app)
        self._state = _RateLimiterState(limit_per_minute)

    async def dispatch(self, request: Request, call_next):
        # Health checks are exempt — orchestration tooling (Docker
        # healthchecks, uptime monitors) polls these frequently and
        # shouldn't compete with real traffic for rate-limit budget.
        if request.url.path in ("/health", "/health/ready"):
            return await call_next(request)

        client_key = request.client.host if request.client else "unknown"
        if not self._state.allow(client_key):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )
        return await call_next(request)
