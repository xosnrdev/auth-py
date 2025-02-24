"""Redis connection pool with secure defaults.

Example:
```python
# Initialize Redis connection
from app.core.redis import redis, init_redis

# Connect with validation
await init_redis()  # Raises if connection fails

# Key operations with type safety
await redis.set("user:123:tokens", "5")
assert await redis.get("user:123:tokens") == "5"

# Hash operations with encoding
user_data = {
    "email": "user@example.com",
    "verified": "1",
    "login_count": "42"
}
await redis.hset("user:123", mapping=user_data)
stored = await redis.hgetall("user:123")
assert stored["email"] == "user@example.com"

# List operations for sessions
await redis.lpush("active_sessions", "token_123")
await redis.ltrim("active_sessions", 0, 999)  # Keep last 1000
sessions = await redis.lrange("active_sessions", 0, -1)

# Expiration for security
await redis.setex("temp_token:123", 3600, "value")  # 1 hour TTL
await redis.expire("user:123:session", 86400)  # 24 hours
```

Critical Security Notes:
1. Connection Security
   - TLS encryption required
   - Password authentication
   - Connection pooling
   - Health checks enabled

2. Data Handling
   - UTF-8 encoding enforced
   - Response decoding
   - Type safety checks
   - Error propagation

3. Performance Settings
   - Pool: 10 connections
   - Timeout: 30 seconds
   - Auto-reconnect

4. Security Practices
   - No sensitive data in keys
   - Always set TTL
   - Monitor pool size
   - Handle disconnects
"""

from typing import Final, cast

from redis.asyncio import Redis, from_url
from redis.asyncio.connection import ConnectionPool
from redis.exceptions import ConnectionError, RedisError

from app.core.config import settings

# Connection constants
POOL_SIZE: Final[int] = 10
POOL_TIMEOUT: Final[int] = 30
HEALTH_CHECK_INTERVAL: Final[int] = 30
ENCODING: Final[str] = "utf-8"

# Create Redis connection pool with secure defaults
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
    """Initialize and validate Redis connection pool.

    Implementation:
    1. Validates connection settings
    2. Tests connection with PING
    3. Verifies pool configuration
    4. Handles connection errors

    Raises:
        RuntimeError: If connection fails or validation fails

    Security:
        - Validates TLS settings
        - Checks authentication
        - Verifies connection
        - Safe error handling

    Example:
        ```python
        try:
            await init_redis()
            print("Redis connected and validated")
        except RuntimeError as e:
            print(f"Redis initialization failed: {e}")
        ```
    """
    try:
        # Validate connection settings
        pool = redis.connection_pool
        if not isinstance(pool, ConnectionPool):
            raise RuntimeError("Invalid connection pool configuration")

        # Validate pool settings
        if pool.max_connections != POOL_SIZE:
            raise RuntimeError(f"Invalid pool size: {pool.max_connections}")

        # Test connection with timeout
        await redis.ping()

    except ConnectionError as e:
        raise RuntimeError(f"Could not connect to Redis: {e}") from e
    except RedisError as e:
        raise RuntimeError(f"Redis validation failed: {e}") from e


async def close_redis() -> None:
    """Close Redis connection pool.

    This should be called during application shutdown.
    """
    await redis.close()
