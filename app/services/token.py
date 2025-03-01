"""Token service for managing access and refresh tokens."""

import logging
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Final, TypedDict, cast
from uuid import UUID, uuid4

from fastapi import HTTPException, Request, Response, status
from jose import JWTError, jwt
from pydantic import BaseModel, Field, field_validator
from redis.asyncio.client import Redis

from app.core.config import settings
from app.core.database import redis

logger = logging.getLogger(__name__)

ALGORITHM: Final[str] = "HS256"
TOKEN_TYPE: Final[str] = "bearer"
REFRESH_TOKEN_KEY_PREFIX: Final[str] = "refresh_token:"
REVOKED_TOKEN_KEY_PREFIX: Final[str] = "revoked_token:"

TOKEN_PREFIX: Final[str] = "token:"
BEARER_FORMAT: Final[str] = "bearer"
COOKIE_MAX_AGE: Final[int] = settings.COOKIE_MAX_AGE_SECS

TOKEN_KEY_PATTERN: Final[str] = TOKEN_PREFIX + "*"
USER_TOKEN_PATTERN: Final[str] = TOKEN_PREFIX + "user:{user_id}:*"
BLACKLIST_PREFIX: Final[str] = "blacklist:"
BLACKLIST_KEY_PATTERN: Final[str] = BLACKLIST_PREFIX + "*"


class TokenType(str, Enum):
    """Token types following OAuth2 specification."""

    ACCESS = "access"
    REFRESH = "refresh"


class TokenResponse(TypedDict):
    """OAuth2 token response format (RFC 6749)."""

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload with validation."""

    sub: str = Field(min_length=32, max_length=36)
    exp: datetime
    iat: datetime
    jti: str = Field(min_length=32, max_length=36)
    type: TokenType

    @field_validator("exp", "iat")
    @classmethod
    def validate_timestamps(cls, v: datetime) -> datetime:
        """Ensure timestamps are UTC."""
        assert v.tzinfo is not None, "Timestamp must be timezone-aware"
        return v.astimezone(UTC)


class TokenMetadata(TypedDict):
    """Token metadata for security tracking.

    Used for:
    - Session management
    - Security monitoring
    - Audit logging
    - Token revocation
    """

    user_id: str
    user_agent: str
    ip_address: str


class TokenService:
    """JWT token service with security features."""

    def __init__(self) -> None:
        """Initialize with secure defaults."""
        assert settings.JWT_SECRET, "JWT secret must be configured"
        self.secret = settings.JWT_SECRET.get_secret_value()

    async def create_tokens(
        self,
        user_id: UUID,
        user_agent: str,
        ip_address: str,
        request: Request | None = None,
        response: Response | None = None,
    ) -> TokenResponse | None:
        """Create access and refresh tokens securely."""
        access_token = await self.create_access_token(user_id)
        refresh_token = await self.create_refresh_token(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Web client: Set secure cookie and store access token in session
        if response and request and hasattr(request, "session"):
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=COOKIE_MAX_AGE,
                expires=int(
                    (datetime.now(UTC) + timedelta(seconds=COOKIE_MAX_AGE)).timestamp()
                ),
            )
            request.session["access_token"] = access_token
            return None

        # API client: Return tokens
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=BEARER_FORMAT,
            expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
        )

    async def create_access_token(self, user_id: UUID) -> str:
        """Create short-lived access token."""
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=settings.JWT_ACCESS_TOKEN_TTL_SECS)
        token_id = uuid4().hex

        payload = TokenPayload(
            sub=user_id.hex,
            exp=expires,
            iat=now,
            jti=token_id,
            type=TokenType.ACCESS,
        )

        return jwt.encode(
            claims=payload.model_dump(),
            key=self.secret,
            algorithm=ALGORITHM,
        )

    async def create_refresh_token(
        self,
        user_id: UUID,
        user_agent: str,
        ip_address: str,
    ) -> str:
        """Create long-lived refresh token."""
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=settings.JWT_REFRESH_TOKEN_TTL_SECS)
        token_id = uuid4().hex

        payload = TokenPayload(
            sub=str(user_id),
            exp=expires,
            iat=now,
            jti=token_id,
            type=TokenType.REFRESH,
        )

        await self._store_token_metadata(
            token_id=token_id,
            user_id=str(user_id),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        return jwt.encode(
            claims=payload.model_dump(),
            key=self.secret,
            algorithm=ALGORITHM,
        )

    async def verify_token(
        self,
        token: str,
        token_type: TokenType = TokenType.ACCESS,
    ) -> TokenPayload:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token=token,
                key=self.secret,
                algorithms=[ALGORITHM],
            )
            token_data = TokenPayload(**payload)

            if token_data.type != token_type:
                raise ValueError("Invalid token type")

            if token_type == TokenType.ACCESS:
                is_blacklisted = await self._is_token_blacklisted(token_data.jti)
                if is_blacklisted:
                    raise ValueError("Token has been revoked")

            if token_type == TokenType.REFRESH:
                metadata = await self.get_token_metadata(token_data.jti)
                if not metadata:
                    raise ValueError("Token revoked")

            return token_data

        except (JWTError, ValueError) as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    async def get_token_metadata(self, token_id: str) -> TokenMetadata | None:
        """Get token metadata from Redis."""
        key = f"{TOKEN_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            result = await cast(Any, redis_client.hgetall(key))
            if not result:
                return None

            data: dict[bytes, bytes] = cast(dict[bytes, bytes], result)
            return TokenMetadata(
                user_id=data[b"user_id"].decode(),
                user_agent=data[b"user_agent"].decode(),
                ip_address=data[b"ip_address"].decode(),
            )
        except Exception:
            return None

    async def _store_token_metadata(
        self,
        token_id: str,
        user_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Store token metadata in Redis."""
        key = f"{TOKEN_PREFIX}{token_id}"
        metadata = {
            b"user_id": user_id.encode(),
            b"user_agent": user_agent.encode(),
            b"ip_address": ip_address.encode(),
        }
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            await cast(Any, redis_client.hmset(key, metadata))
            await cast(
                Any, redis_client.expire(key, settings.JWT_REFRESH_TOKEN_TTL_SECS)
            )
        except Exception as e:
            logger.error("Failed to store token metadata: %s", str(e))

    async def _is_token_blacklisted(self, token_id: str) -> bool:
        """Check if token is blacklisted."""
        key = f"{BLACKLIST_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            return bool(await cast(Any, redis_client.exists(key)))
        except Exception:
            return False

    async def _blacklist_token(self, token_id: str, expires_in: int) -> None:
        """Add token to blacklist."""
        key = f"{BLACKLIST_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            await cast(Any, redis_client.setex(key, expires_in, "1"))
        except Exception as e:
            logger.error("Failed to blacklist token: %s", str(e))

    async def revoke_token(self, token: str) -> None:
        """Revoke a token."""
        try:
            payload = jwt.decode(
                token=token,
                key=self.secret,
                algorithms=[ALGORITHM],
            )
            token_data = TokenPayload(**payload)

            if token_data.type == TokenType.ACCESS:
                # Blacklist access token until expiration
                expires_in = int((token_data.exp - datetime.now(UTC)).total_seconds())
                if expires_in > 0:
                    await self._blacklist_token(token_data.jti, expires_in)

            elif token_data.type == TokenType.REFRESH:
                # Delete refresh token metadata
                key = f"{TOKEN_PREFIX}{token_data.jti}"
                redis_client = Redis(connection_pool=redis.connection_pool)
                await cast(Any, redis_client.delete(key))

        except (JWTError, ValueError):
            pass

    async def revoke_all_user_tokens(
        self,
        user_id: str,
        exclude_token_id: str | None = None,
    ) -> None:
        """Revoke all tokens for a user."""
        pattern = USER_TOKEN_PATTERN.format(user_id=user_id)
        redis_client = Redis(connection_pool=redis.connection_pool)

        try:
            # Scan for all user tokens
            cursor = 0
            while True:
                cursor, keys = await cast(
                    Any,
                    redis_client.scan(cursor, match=pattern),
                )
                for key in keys:
                    token_id = key.decode().split(":")[-1]
                    if token_id != exclude_token_id:
                        await cast(Any, redis_client.delete(key))

                if cursor == 0:
                    break

        except Exception as e:
            logger.error("Failed to revoke user tokens: %s", str(e))


token_service = TokenService()

__all__ = [
    "TokenPayload",
    "TokenResponse",
    "TokenService",
    "TokenType",
    "token_service",
]
