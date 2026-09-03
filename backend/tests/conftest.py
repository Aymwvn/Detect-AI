"""
Shared pytest fixtures for API integration tests: an in-memory SQLite
database (all tables created) plus a real ASGI-transport HTTP client wired
to use it via FastAPI's dependency override, instead of the app's default
(Postgres) DATABASE_URL.

StaticPool note: by default, each new connection to `sqlite:///:memory:`
gets its own separate, empty in-memory database — a well-known SQLite
gotcha. Since the API client fixture opens a fresh session per request
(realistic production behavior) while `db_session` opens another for
direct test setup, both need to resolve to the SAME underlying connection
or seeded data (e.g. a Connector row created via db_session) would be
invisible to the request that's supposed to use it. StaticPool forces
every session from this engine to reuse one shared connection, which
fixes that without changing anything about how the app itself is written.
"""

import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.models import Base
from app.db.session import get_db
from app.main import app


@pytest_asyncio.fixture
async def test_engine():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine):
    session_maker = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session


@pytest_asyncio.fixture
async def client(test_engine):
    session_maker = async_sessionmaker(bind=test_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_maker() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    app.dependency_overrides.clear()
