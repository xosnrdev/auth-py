"""Test configuration and fixtures."""

import asyncio
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.api.v1.auth.router import router as auth_router
from app.core.middleware import RateLimitMiddleware
from app.core.security import get_password_hash
from app.db.base import get_db
from app.models import User
from app.models.base import Base

###########################
# Testcontainers fixtures
###########################

@pytest.fixture(scope="session")
def postgres_container() -> Generator[Any]:
    from testcontainers.postgres import PostgresContainer
    with PostgresContainer("postgres:17.3-alpine3.21") as postgres:
        yield postgres

@pytest.fixture(scope="session")
def redis_container() -> Generator[Any]:
    from testcontainers.redis import RedisContainer
    with RedisContainer("redis:7.4.2-alpine3.21") as redis_cont:
        yield redis_cont


@pytest.fixture(scope="function")
async def redis_client(redis_container: Any) -> AsyncGenerator[Redis]:
    """Create a Redis client for testing using testcontainers."""
    client = Redis(
        host=redis_container.get_container_host_ip(),
        port=int(redis_container.get_exposed_port(6379))
    )
    connection_pool: Any = client.connection_pool
    connection_pool.loop = asyncio.get_running_loop()
    try:
        await client.ping()  # Test connection
        # Clear any existing rate limit keys
        async for key in client.scan_iter("rate_limit:*"):
            await client.delete(key)
        yield client
    finally:
        await client.aclose()


@pytest.fixture(scope="function")
async def test_engine(postgres_container: Any) -> AsyncGenerator[AsyncEngine]:
    """Create test database engine using the Postgres container with asyncpg driver."""
    import re
    url = postgres_container.get_connection_url()
    url = re.sub(r"^postgresql(?:\+psycopg2)?://", "postgresql+asyncpg://", url)
    engine = create_async_engine(
        url,
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


@pytest.fixture(scope="function")
def async_session_maker(test_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create async session maker."""
    return async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )


@pytest.fixture(scope="function")
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


@pytest.fixture(scope="function")
async def test_app(
    test_session: AsyncSession,
    redis_client: Redis,
) -> FastAPI:
    """Create a test FastAPI application."""
    app = FastAPI()

    # Add middleware
    app.add_middleware(RateLimitMiddleware, redis_client=redis_client)

    # Add routes
    app.include_router(auth_router, prefix="/api/v1")

    async def get_test_db() -> AsyncGenerator[AsyncSession]:
        try:
            yield test_session
        finally:
            await test_session.close()

    # Override dependencies
    app.dependency_overrides = {
        get_db: get_test_db,
    }

    # Override Redis client
    import app.core.redis as redis_module
    redis_module.redis = redis_client
    connection_pool: Any = redis_module.redis.connection_pool
    connection_pool.loop = asyncio.get_running_loop()

    # Override setex to bypass actual Redis operations and avoid event loop errors during tests
    async def fake_setex(*_args: Any, **_kwargs: Any) -> bool:
        return True
    redis_module.redis.setex = fake_setex  # type: ignore

    # Also patch the tokens module to use the test Redis client and our fake_setex
    import app.core.jwt.tokens as tokens_module
    tokens_module.redis = redis_client  # type: ignore
    tokens_module.redis.setex = fake_setex  # type: ignore

    return app


@pytest.fixture(scope="function")
async def test_client(test_app: FastAPI) -> AsyncGenerator[httpx.AsyncClient]:
    """Create test client."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=test_app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture(scope="function")
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


@pytest.fixture(autouse=True)
async def mock_email_service() -> AsyncGenerator[AsyncMock]:
    """Mock email service for all tests."""
    with patch("app.core.email.EmailService._send_email", new_callable=AsyncMock) as mock:
        mock.return_value = None
        yield mock
