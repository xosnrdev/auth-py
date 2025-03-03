"""Token repository for managing token storage and retrieval."""

import logging
from typing import Any, cast

from redis.asyncio.client import Redis

from app.core.database import redis
from app.schemas.token import TokenMetadata

logger = logging.getLogger(__name__)

TOKEN_PREFIX = "token:"
BLACKLIST_PREFIX = "blacklist:"
TOKEN_KEY_PATTERN = TOKEN_PREFIX + "*"
USER_TOKEN_PATTERN = TOKEN_PREFIX + "user:{user_id}:*"


class TokenRepository:
    """Repository for managing token storage and retrieval in Redis."""

    async def get_token_metadata(self, token_id: str) -> TokenMetadata | None:
        """Get token metadata from Redis.

        Args:
            token_id: Token ID to get metadata for

        Returns:
            Token metadata if found, None otherwise
        """
        # Try both old and new key formats
        keys = [
            f"{TOKEN_PREFIX}{token_id}",  # Old format
            f"{TOKEN_PREFIX}user:*:{token_id}",  # New format
        ]

        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            # For new format, we need to find the actual key first
            matching_keys = []
            for pattern in keys:
                if "*" in pattern:
                    found_keys = await redis_client.keys(pattern)
                    matching_keys.extend(found_keys)
                else:
                    matching_keys.append(
                        pattern.encode() if isinstance(pattern, str) else pattern
                    )

            # Try each potential key
            for key in matching_keys:
                key_str = key.decode() if isinstance(key, bytes) else key
                result = await cast(Any, redis_client.hgetall(key_str))
                if result:
                    try:
                        # Handle both byte and string keys in the result
                        user_id_key = b"user_id" if b"user_id" in result else "user_id"
                        user_agent_key = (
                            b"user_agent" if b"user_agent" in result else "user_agent"
                        )
                        ip_address_key = (
                            b"ip_address" if b"ip_address" in result else "ip_address"
                        )

                        user_id = result[user_id_key]
                        user_agent = result[user_agent_key]
                        ip_address = result[ip_address_key]

                        # Decode if bytes
                        user_id = (
                            user_id.decode() if isinstance(user_id, bytes) else user_id
                        )
                        user_agent = (
                            user_agent.decode()
                            if isinstance(user_agent, bytes)
                            else user_agent
                        )
                        ip_address = (
                            ip_address.decode()
                            if isinstance(ip_address, bytes)
                            else ip_address
                        )

                        return TokenMetadata(
                            user_id=user_id,
                            user_agent=user_agent,
                            ip_address=ip_address,
                        )
                    except Exception as e:
                        logger.error(
                            "Failed to process token metadata: %s, data: %s",
                            str(e),
                            result,
                        )
                        continue

            return None
        except Exception as e:
            logger.error("Failed to get token metadata: %s", str(e))
            return None

    async def store_token_metadata(
        self,
        token_id: str,
        metadata: dict[bytes, bytes],
        ttl: int,
        key: str | None = None,
    ) -> None:
        """Store token metadata in Redis.

        Args:
            token_id: Token ID to store metadata for
            metadata: Token metadata to store
            ttl: Time to live in seconds
            key: Optional custom key to use for storage
        """
        storage_key = key if key else f"{TOKEN_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            await cast(Any, redis_client.hmset(storage_key, metadata))
            await cast(Any, redis_client.expire(storage_key, ttl))
        except Exception as e:
            logger.error("Failed to store token metadata: %s", str(e))

    async def is_token_blacklisted(self, token_id: str) -> bool:
        """Check if token is blacklisted.

        Args:
            token_id: Token ID to check

        Returns:
            True if token is blacklisted, False otherwise
        """
        key = f"{BLACKLIST_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            return bool(await redis_client.exists(key))
        except Exception as e:
            logger.error("Failed to check token blacklist: %s", str(e))
            return False

    async def blacklist_token(self, token_id: str, expires_in: int) -> None:
        """Add token to blacklist.

        Args:
            token_id: Token ID to blacklist
            expires_in: Time until token expires in seconds
        """
        key = f"{BLACKLIST_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            await redis_client.setex(key, expires_in, "1")
        except Exception as e:
            logger.error("Failed to blacklist token: %s", str(e))

    async def delete_token(self, token_id: str) -> None:
        """Delete token metadata.

        Args:
            token_id: Token ID to delete
        """
        # Try both old and new key formats
        keys = [
            f"{TOKEN_PREFIX}{token_id}",  # Old format
            f"{TOKEN_PREFIX}user:*:{token_id}",  # New format
        ]

        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            # For new format, we need to find the actual key first
            matching_keys = []
            for pattern in keys:
                if "*" in pattern:
                    found_keys = await redis_client.keys(pattern)
                    matching_keys.extend(found_keys)
                else:
                    matching_keys.append(
                        pattern.encode() if isinstance(pattern, str) else pattern
                    )

            # Delete each matching key
            for key in matching_keys:
                key_str = key.decode() if isinstance(key, bytes) else key
                await redis_client.delete(key_str)
        except Exception as e:
            logger.error("Failed to delete token: %s", str(e))

    async def delete_user_tokens(self, user_id: str) -> None:
        """Delete all tokens for a user.

        Args:
            user_id: User ID to delete tokens for
        """
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            pattern = USER_TOKEN_PATTERN.format(user_id=user_id)
            keys = await redis_client.keys(pattern)
            if keys:
                await redis_client.delete(*keys)
        except Exception as e:
            logger.error("Failed to delete user tokens: %s", str(e))

    async def get_user_token_keys(self, user_id: str) -> list[str]:
        """Get all token keys for a user.

        Args:
            user_id: User ID to get tokens for

        Returns:
            List of token keys

        Raises:
            RuntimeError: If Redis operation fails
        """
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            # Verify Redis connection
            if not await redis_client.ping():
                raise RuntimeError("Redis connection failed")

            pattern = USER_TOKEN_PATTERN.format(user_id=user_id)
            keys = await redis_client.keys(pattern)
            return [key.decode() if isinstance(key, bytes) else key for key in keys]
        except Exception as e:
            logger.error("Failed to get user token keys: %s", str(e))
            raise RuntimeError(f"Failed to get user token keys: {str(e)}")

    async def bulk_revoke_tokens(
        self, token_keys: list[str], blacklist_ttl: int
    ) -> None:
        """Revoke multiple tokens atomically.

        Args:
            token_keys: List of token keys to revoke
            blacklist_ttl: Time to live for blacklist entries

        Raises:
            RuntimeError: If Redis operations fail
        """
        if not token_keys:
            return

        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            pipe = redis_client.pipeline()
            operations_count = 0

            for key in token_keys:
                token_id = key.split(":")[-1]

                # Add token to blacklist
                blacklist_key = f"{BLACKLIST_PREFIX}{token_id}"
                pipe.setex(blacklist_key, blacklist_ttl, "1")
                operations_count += 1

                # Delete token metadata
                pipe.delete(key)
                operations_count += 1

            # Execute all operations atomically
            results = await pipe.execute()

            # Verify all operations succeeded
            if len(results) != operations_count:
                raise RuntimeError(
                    f"Expected {operations_count} operations, got {len(results)}"
                )
            if not all(r is not None for r in results):
                raise RuntimeError("Some Redis operations failed")

        except Exception as e:
            logger.error("Failed to revoke tokens in bulk: %s", str(e))
            raise RuntimeError(f"Failed to revoke tokens in bulk: {str(e)}")
