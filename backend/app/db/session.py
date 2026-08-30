"""Async SQLAlchemy engine/session setup.

Uses the DATABASE_URL from Settings (postgresql+asyncpg://... in production,
overridable to sqlite+aiosqlite:// for local/dev testing without a running
Postgres instance).
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import get_settings

settings = get_settings()

engine = create_async_engine(settings.database_url, echo=settings.debug, future=True)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a session, always closes it after the request."""
    async with AsyncSessionLocal() as session:
        yield session
