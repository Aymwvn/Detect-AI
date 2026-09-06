"""
DetectAI backend entrypoint.

Run locally:
    uvicorn app.main:app --reload --port 8000

Docs once running:
    http://localhost:8000/docs
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import alerts, auth, health, mitre, webhooks
from app.core.config import get_settings
from app.core.logging_config import configure_logging
from app.core.rate_limit import RateLimitMiddleware

settings = get_settings()
configure_logging(debug=settings.debug)

app = FastAPI(
    title=settings.app_name,
    description="Evidence-first, SIEM-agnostic AI security alert triage & investigation engine.",
    version="0.1.0",
    docs_url="/docs" if settings.environment != "production" else None,
)

app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# health check has no prefix — used by orchestration tooling directly at /health
app.include_router(health.router)
app.include_router(auth.router, prefix=settings.api_v1_prefix)
app.include_router(alerts.router, prefix=settings.api_v1_prefix)
app.include_router(webhooks.router, prefix=settings.api_v1_prefix)
app.include_router(mitre.router, prefix=settings.api_v1_prefix)


@app.get("/")
async def root() -> dict:
    return {
        "name": settings.app_name,
        "version": "0.1.0",
        "docs": "/docs",
    }
