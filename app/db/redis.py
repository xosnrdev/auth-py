"""Redis connection pool with secure defaults."""

from typing import Final, cast

from redis.asyncio import Redis, from_url
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import ConnectionError, RedisError

from app.core.config import settings

POOL_SIZE: Final[int] = 10
POOL_TIMEOUT: Final[int] = 30
HEALTH_CHECK_INTERVAL: Final[int] = 30
ENCODING: Final[str] = "utf-8"

redis: Redis = cast(
    Redis,
    from_url(  # type: ignore[no-untyped-call]
        url=settings.REDIS_URI.unicode_string(),
        encoding=ENCODING,
        decode_responses=True,
        max_connections=POOL_SIZE,
        socket_timeout=POOL_TIMEOUT,
        socket_keepalive=True,
        health_check_interval=HEALTH_CHECK_INTERVAL,
        retry_on_timeout=True
    ),
)


async def init_redis() -> None:
    """Initialize and validate Redis connection pool."""
    try:
        pool = redis.connection_pool
        if not isinstance(pool, ConnectionPool):
            raise RuntimeError("Invalid connection pool configuration")

        if pool.max_connections != POOL_SIZE:
            raise RuntimeError(f"Invalid pool size: {pool.max_connections}")

        await redis.ping()

    except ConnectionError as e:
        raise RuntimeError(f"Could not connect to Redis: {e}") from e
    except RedisError as e:
        raise RuntimeError(f"Redis validation failed: {e}") from e


async def close_redis() -> None:
    """Close Redis connection pool."""
    await redis.close()
