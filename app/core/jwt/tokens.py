"""JWT token service following RFC 9068."""

import logging
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import TypedDict
from uuid import UUID, uuid4

from fastapi import Response
from jose import JWTError, jwt
from pydantic import BaseModel

from app.core.config import settings
from app.core.redis import redis

logger = logging.getLogger(__name__)

# JWT algorithm
ALGORITHM = "HS256"


class TokenType(str, Enum):
    """Token types following RFC 6749."""

    ACCESS = "access"
    REFRESH = "refresh"


class TokenResponse(TypedDict):
    """Token response for API clients."""

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # User ID in hex format
    exp: datetime  # Expiration time
    iat: datetime  # Issued at
    jti: str  # JWT ID in hex format
    type: TokenType  # Token type


class TokenMetadata(TypedDict):
    """Token metadata for storage."""

    user_id: str
    user_agent: str
    ip_address: str


class TokenService:
    """JWT token service with Redis-backed revocation."""

    def __init__(self) -> None:
        """Initialize token service."""
        self.secret = settings.JWT_SECRET

    async def create_tokens(
        self,
        user_id: UUID,
        user_agent: str,
        ip_address: str,
        response: Response | None = None,
    ) -> TokenResponse | None:
        """Create access and refresh tokens with metadata.

        Args:
            user_id: User ID to include in token
            user_agent: User agent string for metadata
            ip_address: IP address for metadata
            response: Optional FastAPI response for cookie-based delivery

        Returns:
            TokenResponse | None: Tokens if no response object provided
        """
        access_token = await self.create_access_token(user_id)
        refresh_token = await self.create_refresh_token(user_id, user_agent, ip_address)

        # If response object is provided, set cookies (web flow)
        if response:
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=settings.COOKIE_MAX_AGE_SECS,
                expires=int((datetime.now(UTC) + timedelta(seconds=settings.COOKIE_MAX_AGE_SECS)).timestamp()),
            )
            return None

        # Otherwise return tokens as JSON (mobile/API flow)
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRES_SECS,
        )

    async def create_access_token(self, user_id: UUID) -> str:
        """Create a new access token.

        Args:
            user_id: User ID to include in token

        Returns:
            str: Signed JWT access token

        Raises:
            JWTError: If token creation fails
        """
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=settings.JWT_ACCESS_TOKEN_EXPIRES_SECS)
        token_id = uuid4()

        payload = TokenPayload(
            sub=user_id.hex,
            exp=expires,
            iat=now,
            jti=token_id.hex,
            type=TokenType.ACCESS,
        )

        try:
            token = jwt.encode(
                claims=payload.model_dump(),
                key=self.secret,
                algorithm=ALGORITHM,
            )
            return token
        except JWTError as e:
            logger.error("Failed to create access token: %s", str(e))
            raise

    async def create_refresh_token(
        self,
        user_id: UUID,
        user_agent: str,
        ip_address: str,
    ) -> str:
        """Create a new refresh token with metadata.

        Args:
            user_id: User ID to include in token
            user_agent: User agent string for metadata
            ip_address: IP address for metadata

        Returns:
            str: Signed JWT refresh token

        Raises:
            JWTError: If token creation fails
        """
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=settings.JWT_REFRESH_TOKEN_EXPIRES_SECS)
        token_id = uuid4()

        payload = TokenPayload(
            sub=user_id.hex,
            exp=expires,
            iat=now,
            jti=token_id.hex,
            type=TokenType.REFRESH,
        )

        try:
            token = jwt.encode(
                claims=payload.model_dump(),
                key=self.secret,
                algorithm=ALGORITHM,
            )

            # Store refresh token and metadata in Redis
            await self._store_token_metadata(
                token_id=token_id.hex,
                user_id=user_id.hex,
                user_agent=user_agent,
                ip_address=ip_address,
            )

            return token
        except JWTError as e:
            logger.error("Failed to create refresh token: %s", str(e))
            raise

    async def verify_token(
        self,
        token: str,
        token_type: TokenType = TokenType.ACCESS,
    ) -> TokenPayload:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify
            token_type: Expected token type (access or refresh)

        Returns:
            TokenPayload: Decoded token payload

        Raises:
            JWTError: If token is invalid or revoked
        """
        try:
            # Decode and verify token
            payload = jwt.decode(
                token=token,
                key=self.secret,
                algorithms=[ALGORITHM],
            )
            token_data = TokenPayload(**payload)

            # Check token type
            if token_data.type != token_type:
                raise JWTError(f"Invalid token type. Expected {token_type}, got {token_data.type}")

            # Check if refresh token is revoked
            if token_type == TokenType.REFRESH:
                metadata = await self.get_token_metadata(token_data.jti)
                if not metadata or metadata["user_id"] != token_data.sub:
                    raise JWTError("Token has been revoked")

            return token_data

        except JWTError as e:
            logger.error("Failed to verify token: %s", str(e))
            raise

    async def get_token_metadata(self, token_id: str) -> TokenMetadata | None:
        """Get metadata for a refresh token.

        Args:
            token_id: Token ID (jti claim)

        Returns:
            TokenMetadata | None: Token metadata if found
        """
        user_id = await redis.get(f"refresh_token:{token_id}")
        if not user_id:
            return None

        user_agent = await redis.get(f"user_agent:{token_id}") or ""
        ip_address = await redis.get(f"ip_address:{token_id}") or ""

        return TokenMetadata(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )

    async def _store_token_metadata(
        self,
        token_id: str,
        user_id: str,
        user_agent: str,
        ip_address: str,
    ) -> None:
        """Store refresh token metadata in Redis.

        Args:
            token_id: Token ID (jti claim)
            user_id: User ID in hex format
            user_agent: User agent string
            ip_address: IP address
        """
        # Store token and metadata with expiration
        await redis.setex(
            f"refresh_token:{token_id}",
            settings.JWT_REFRESH_TOKEN_EXPIRES_SECS,
            user_id,
        )
        await redis.setex(
            f"user_agent:{token_id}",
            settings.JWT_REFRESH_TOKEN_EXPIRES_SECS,
            user_agent,
        )
        await redis.setex(
            f"ip_address:{token_id}",
            settings.JWT_REFRESH_TOKEN_EXPIRES_SECS,
            ip_address,
        )

    async def revoke_token(self, token: str) -> None:
        """Revoke a refresh token and its metadata.

        Args:
            token: JWT refresh token to revoke

        Raises:
            JWTError: If token is invalid or already revoked
        """
        try:
            # Verify token first
            token_data = await self.verify_token(token, TokenType.REFRESH)

            # Remove token and metadata from Redis
            await redis.delete(f"refresh_token:{token_data.jti}")
            await redis.delete(f"user_agent:{token_data.jti}")
            await redis.delete(f"ip_address:{token_data.jti}")

            logger.info("Revoked refresh token for user %s", token_data.sub)

        except JWTError as e:
            logger.error("Failed to revoke token: %s", str(e))
            raise

    async def revoke_all_user_tokens(
        self,
        user_id: str,
        exclude_token_id: str | None = None,
    ) -> None:
        """Revoke all refresh tokens for a user.

        Args:
            user_id: User ID in hex format
            exclude_token_id: Optional token ID to exclude from revocation
        """
        pattern = "refresh_token:*"
        async for key in redis.scan_iter(pattern):
            if not isinstance(key, str):  # Type guard
                continue

            stored_user_id = await redis.get(key)
            if stored_user_id == user_id:
                token_id = key.split(":")[-1]
                if token_id != exclude_token_id:
                    await redis.delete(f"refresh_token:{token_id}")
                    await redis.delete(f"user_agent:{token_id}")
                    await redis.delete(f"ip_address:{token_id}")


# Create global token service instance
token_service = TokenService()
