"""Redis client for session management."""

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


async def set_session(
    session_id: str,
    user_id: str,
    expires_in: int = settings.COOKIE_MAX_AGE,
) -> None:
    """Store session data in Redis.

    Args:
        session_id: Unique session identifier
        user_id: User ID associated with the session
        expires_in: Session expiration time in seconds
    """
    key = f"session:{session_id}"
    await redis.set(key, user_id, ex=expires_in)


async def get_session(session_id: str) -> str | None:
    """Get user ID from session.

    Args:
        session_id: Session identifier

    Returns:
        str | None: User ID if session exists and is valid
    """
    key = f"session:{session_id}"
    result = await redis.get(key)
    return cast(str | None, result)


async def delete_session(session_id: str) -> None:
    """Delete a session from Redis.

    Args:
        session_id: Session identifier to delete
    """
    key = f"session:{session_id}"
    await redis.delete(key)
