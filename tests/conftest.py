"""Test configuration and fixtures."""

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, patch

import httpx
import pytest_asyncio
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api.v1.auth.router import router as auth_router
from app.core.config import get_settings
from app.core.security import get_password_hash
from app.db.base import get_db
from app.models import User
from app.models.base import Base

# Set default event loop policy for pytest-asyncio
pytest_plugins = ("pytest_asyncio",)

@pytest_asyncio.fixture(scope="function")
async def test_engine() -> AsyncGenerator[AsyncEngine]:
    """Create test database engine."""
    settings = get_settings()
    engine = create_async_engine(
        settings.DATABASE_URI.unicode_string(),
        echo=True,
        pool_pre_ping=True,
        isolation_level="REPEATABLE READ",
    )

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield engine
    finally:
        await engine.dispose()


@pytest_asyncio.fixture(scope="function")
def async_session_maker(test_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create async session maker."""
    return async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


@pytest_asyncio.fixture(scope="function")
async def test_session(
    async_session_maker: async_sessionmaker[AsyncSession],
) -> AsyncGenerator[AsyncSession]:
    """Create test database session."""
    async with async_session_maker() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


@pytest_asyncio.fixture(scope="function")
async def test_app(test_session: AsyncSession) -> FastAPI:
    """Create a test FastAPI application."""
    app = FastAPI()
    app.include_router(auth_router, prefix="/api/v1")

    async def get_test_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield test_session
        finally:
            await test_session.close()

    app.dependency_overrides = {
        get_db: get_test_db,
    }

    return app


@pytest_asyncio.fixture(scope="function")
async def test_client(test_app: FastAPI) -> AsyncGenerator[httpx.AsyncClient]:
    """Create test client."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url="http://test",
    ) as client:
        yield client


@pytest_asyncio.fixture(scope="function")
async def test_user(test_session: AsyncSession) -> User:
    """Create a test user."""
    user = User(
        email="test@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=True,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


@pytest_asyncio.fixture(autouse=True)
async def mock_email_service() -> AsyncGenerator[AsyncMock]:
    """Mock email service for all tests."""
    with patch("app.core.email.EmailService._send_email", new_callable=AsyncMock) as mock:
        mock.return_value = None
        yield mock
