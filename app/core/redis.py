"""Redis client for token revocation and rate limiting."""

from typing import cast

from redis.asyncio import Redis, from_url

from app.core.config import settings

# Create Redis pool
redis: Redis = cast(Redis, from_url(  # type: ignore[no-untyped-call]
    settings.REDIS_URI.unicode_string(),
    encoding="utf-8",
    decode_responses=True,
))


async def init_redis() -> None:
    """Initialize Redis connection pool.

    This should be called during application startup.
    """
    try:
        await redis.ping()
    except Exception as e:
        raise RuntimeError(f"Could not connect to Redis: {e}") from e


async def close_redis() -> None:
    """Close Redis connection pool.

    This should be called during application shutdown.
    """
    await redis.close()
