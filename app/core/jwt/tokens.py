"""JWT token service following RFC 9068."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Literal, TypedDict
from uuid import UUID, uuid4

from fastapi import Response
from jose import JWTError, jwt
from pydantic import BaseModel

from app.core.config import settings
from app.core.redis import redis

logger = logging.getLogger(__name__)

# JWT algorithm
ALGORITHM = "HS256"


class TokenResponse(TypedDict):
    """Token response for API clients."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # User ID in hex format
    exp: datetime  # Expiration time
    iat: datetime  # Issued at
    jti: str  # JWT ID in hex format
    type: Literal["access", "refresh"]  # Token type


class TokenService:
    """JWT token service with Redis-backed revocation."""

    def __init__(self) -> None:
        """Initialize token service."""
        self.secret = settings.JWT_SECRET

    async def create_tokens(
        self,
        user_id: UUID,
        response: Response | None = None,
    ) -> TokenResponse | None:
        """Create access and refresh tokens.

        Args:
            user_id: User ID to include in token
            response: Optional FastAPI response for cookie-based delivery

        Returns:
            TokenResponse | None: Tokens if no response object provided
        """
        access_token = await self.create_access_token(user_id)
        refresh_token = await self.create_refresh_token(user_id)

        # If response object is provided, set cookies (web flow)
        if response:
            response.set_cookie(
                key=settings.COOKIE_NAME,
                value=refresh_token,
                httponly=settings.COOKIE_HTTPONLY,
                secure=settings.COOKIE_SECURE,
                samesite=settings.COOKIE_SAMESITE,
                max_age=settings.COOKIE_MAX_AGE_SECS,
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
            type="access",
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

    async def create_refresh_token(self, user_id: UUID) -> str:
        """Create a new refresh token.

        Args:
            user_id: User ID to include in token

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
            type="refresh",
        )

        try:
            token = jwt.encode(
                claims=payload.model_dump(),
                key=self.secret,
                algorithm=ALGORITHM,
            )

            # Store refresh token in Redis for revocation
            await redis.setex(
                f"refresh_token:{token_id.hex}",
                settings.JWT_REFRESH_TOKEN_EXPIRES_SECS,
                user_id.hex,
            )

            return token
        except JWTError as e:
            logger.error("Failed to create refresh token: %s", str(e))
            raise

    async def verify_token(
        self,
        token: str,
        token_type: Literal["access", "refresh"] = "access",
    ) -> TokenPayload:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify
            token_type: Expected token type

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
                raise JWTError("Invalid token type")

            # Check if token is revoked
            if token_type == "refresh":
                user_id = await redis.get(f"refresh_token:{token_data.jti}")
                if not user_id or user_id != token_data.sub:
                    raise JWTError("Token has been revoked")

            return token_data

        except JWTError as e:
            logger.error("Failed to verify token: %s", str(e))
            raise

    async def revoke_token(self, token: str) -> None:
        """Revoke a refresh token.

        Args:
            token: JWT refresh token to revoke

        Raises:
            JWTError: If token is invalid or already revoked
        """
        try:
            # Verify token first
            token_data = await self.verify_token(token, "refresh")

            # Remove from Redis
            result = await redis.delete(f"refresh_token:{token_data.jti}")
            if not result:
                raise JWTError("Token already revoked")

            logger.info("Revoked refresh token for user %s", token_data.sub)

        except JWTError as e:
            logger.error("Failed to revoke token: %s", str(e))
            raise


# Create global token service instance
token_service = TokenService()
