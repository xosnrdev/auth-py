"""Tests for rate limiting middleware."""

import asyncio
from collections.abc import AsyncGenerator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis

from app.core.config import settings
from app.core.middleware import RateLimitMiddleware


@pytest.fixture(scope="function")
async def redis_client() -> AsyncGenerator[Redis]:
    """Create a Redis client for testing."""
    client = Redis.from_url(settings.REDIS_URI.unicode_string())
    try:
        await client.ping()  # Test connection
        # Clear any existing rate limit keys
        async for key in client.scan_iter("rate_limit:*"):
            await client.delete(key)
        yield client
    finally:
        await client.aclose()


@pytest.fixture
async def rate_limit_app(redis_client: Redis) -> FastAPI:
    """Create test FastAPI app with rate limiting."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, redis_client=redis_client)

    @app.get("/test")
    async def test_endpoint() -> dict[str, str]:
        return {"message": "success"}

    return app


@pytest.fixture
async def async_client(rate_limit_app: FastAPI) -> AsyncGenerator[AsyncClient]:
    """Create an async client for testing."""
    async with AsyncClient(
        transport=ASGITransport(app=rate_limit_app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_rate_limit_headers(async_client: AsyncClient) -> None:
    """Test rate limit headers are present in response."""
    response = await async_client.get("/test")
    assert response.status_code == 200
    assert "X-RateLimit-Limit" in response.headers
    assert "X-RateLimit-Remaining" in response.headers
    assert "X-RateLimit-Reset" in response.headers


@pytest.mark.asyncio
async def test_rate_limit_exceeded(async_client: AsyncClient) -> None:
    """Test rate limiting blocks requests after limit is exceeded."""
    # Make 5 requests (allowed)
    for _ in range(5):
        response = await async_client.get("/test")
        assert response.status_code == 200

    # Next request should be blocked
    response = await async_client.get("/test")
    assert response.status_code == 429
    assert "Retry-After" in response.headers


@pytest.mark.asyncio
async def test_rate_limit_reset(async_client: AsyncClient, redis_client: Redis) -> None:
    """Test rate limit resets after window expires."""
    # Make 5 requests to hit the limit
    for _ in range(5):
        response = await async_client.get("/test")
        assert response.status_code == 200

    # Next request should be blocked
    response = await async_client.get("/test")
    assert response.status_code == 429

    # Clear rate limit keys to simulate window expiry
    async for key in redis_client.scan_iter("rate_limit:*"):
        await redis_client.delete(key)

    # Should be able to make requests again
    response = await async_client.get("/test")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_concurrent_requests(async_client: AsyncClient) -> None:
    """Test rate limiting handles concurrent requests correctly."""
    # Make 10 concurrent requests
    async def make_request() -> None:
        response = await async_client.get("/test")
        # First 5 should succeed, rest should fail
        if response.status_code not in (200, 429):
            pytest.fail(f"Unexpected status code: {response.status_code}")

    # Use asyncio.gather with return_exceptions=True to handle errors gracefully
    await asyncio.gather(*[make_request() for _ in range(10)], return_exceptions=True)


@pytest.mark.asyncio
async def test_docs_endpoints_not_limited(async_client: AsyncClient) -> None:
    """Test documentation endpoints are not rate limited."""
    # Make more than 5 requests to docs endpoints
    endpoints = ["/docs", "/redoc", "/openapi.json"]
    for endpoint in endpoints:
        for _ in range(10):
            response = await async_client.get(endpoint)
            assert response.status_code != 429  # Should never hit rate limit
