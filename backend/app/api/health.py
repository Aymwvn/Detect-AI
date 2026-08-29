"""Health and readiness endpoints. Used by Docker Compose healthchecks and
uptime monitoring — deliberately has zero dependencies on DB/Redis so it
always answers even if downstream services are degraded (see /health/ready
for the dependency-aware variant, added once DB/Redis wiring lands)."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    """Liveness check — is the process up at all."""
    return {"status": "ok"}
