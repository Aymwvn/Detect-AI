"""Health and readiness endpoints. Used by Docker Compose healthchecks and
uptime monitoring. /health is a pure liveness check with zero dependencies
so it always answers even if downstream services are degraded; /health/ready
actually touches the database and is what orchestration should gate
traffic/restarts on."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    """Liveness check — is the process up at all."""
    return {"status": "ok"}


@router.get("/health/ready")
async def readiness(db: AsyncSession = Depends(get_db)) -> dict:
    """Readiness check — can we actually reach the database."""
    try:
        await db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database not reachable: {exc}",
        )
    return {"status": "ok", "database": "reachable"}
