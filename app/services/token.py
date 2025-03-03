"""Token service for managing access and refresh tokens."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID, uuid4

from fastapi import HTTPException, Request, Response, status
from jose import JWTError, jwt

from app.core.config import settings
from app.repositories.token import TokenRepository
from app.schemas.token import (
    TokenCreate,
    TokenMetadata,
    TokenPayload,
    TokenResponse,
    TokenType,
)

logger = logging.getLogger(__name__)

ALGORITHM: Final[str] = "HS256"
BEARER_FORMAT: Final[str] = "bearer"

COOKIE_MAX_AGE: Final[int] = settings.COOKIE_MAX_AGE_SECS

TOKEN_PREFIX: Final[str] = "token:"
BLACKLIST_PREFIX: Final[str] = "blacklist:"
USER_TOKEN_PATTERN: Final[str] = TOKEN_PREFIX + "user:{user_id}:*"


class TokenService:
    """JWT token service with security features."""

    def __init__(self, token_repo: TokenRepository) -> None:
        """Initialize with secure defaults and repository.

        Args:
            token_repo: Token repository for storage operations
        """
        assert settings.JWT_SECRET, "JWT secret must be configured"
        self.secret = settings.JWT_SECRET.get_secret_value()
        self._token_repo = token_repo

    async def create_tokens(
        self,
        user_id: UUID,
        user_agent: str,
        ip_address: str,
        request: Request | None = None,
        response: Response | None = None,
    ) -> TokenResponse | None:
        """Create access and refresh tokens securely."""
        access_token_data = TokenCreate(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
            token_type=TokenType.ACCESS,
        )
        access_token = await self.create_token(access_token_data)

        refresh_token_data = TokenCreate(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
            token_type=TokenType.REFRESH,
        )
        refresh_token = await self.create_token(refresh_token_data)

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

    async def create_token(self, token_data: TokenCreate) -> str:
        """Create a new token.

        Args:
            token_data: Token creation data

        Returns:
            Encoded JWT token string
        """
        now = datetime.now(UTC)
        token_id = uuid4().hex

        if token_data.expires_in:
            expires_in = token_data.expires_in
        else:
            expires_in = (
                settings.JWT_ACCESS_TOKEN_TTL_SECS
                if token_data.token_type == TokenType.ACCESS
                else settings.JWT_REFRESH_TOKEN_TTL_SECS
            )
        expires = now + timedelta(seconds=expires_in)

        payload = TokenPayload(
            sub=token_data.user_id.hex,
            exp=expires,
            iat=now,
            jti=token_id,
            type=token_data.token_type,
        )

        await self._store_token_metadata(
            token_id=token_id,
            user_id=token_data.user_id.hex,
            user_agent=token_data.user_agent,
            ip_address=token_data.ip_address,
            ttl=expires_in,
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
                is_blacklisted = await self._token_repo.is_token_blacklisted(
                    token_data.jti
                )
                if is_blacklisted:
                    raise ValueError("Token has been revoked")

            if token_type == TokenType.REFRESH:
                metadata = await self._token_repo.get_token_metadata(token_data.jti)
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
        """Get token metadata from repository."""
        return await self._token_repo.get_token_metadata(token_id)

    async def _store_token_metadata(
        self,
        token_id: str,
        user_id: str,
        user_agent: str,
        ip_address: str,
        ttl: int,
    ) -> None:
        """Store token metadata in repository."""
        # Store token metadata with user ID in key
        key = f"{TOKEN_PREFIX}user:{user_id}:{token_id}"
        metadata = {
            b"user_id": user_id.encode(),
            b"user_agent": user_agent.encode(),
            b"ip_address": ip_address.encode(),
        }
        await self._token_repo.store_token_metadata(
            token_id=token_id,
            metadata=metadata,
            ttl=ttl,
            key=key,
        )

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
                    await self._token_repo.blacklist_token(token_data.jti, expires_in)

            elif token_data.type == TokenType.REFRESH:
                # Delete refresh token metadata
                await self._token_repo.delete_token(token_data.jti)

        except (JWTError, ValueError) as e:
            logger.error("Failed to revoke token: %s", str(e))

    async def revoke_all_user_tokens(self, user_id: str) -> None:
        """Revoke all tokens for a user."""
        assert len(user_id) == 32 or (len(user_id) == 36 and user_id.count("-") == 4), (
            "Invalid user_id format"
        )

        try:
            # Get all token keys for the user
            token_keys = await self._token_repo.get_user_token_keys(user_id)

            # Bulk revoke all tokens
            await self._token_repo.bulk_revoke_tokens(
                token_keys=token_keys,
                blacklist_ttl=settings.JWT_ACCESS_TOKEN_TTL_SECS,
            )

        except AssertionError as e:
            logger.error("Validation failed in revoke_all_user_tokens: %s", str(e))
            raise ValueError(str(e))
        except Exception as e:
            logger.error("Failed to revoke user tokens: %s", str(e))
            raise RuntimeError(f"Failed to revoke user tokens: {str(e)}")


token_service = TokenService(TokenRepository())

__all__ = [
    "TokenPayload",
    "TokenResponse",
    "TokenService",
    "TokenType",
    "TokenCreate",
    "token_service",
]
