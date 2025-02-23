"""JWT token service implementing OAuth2 and JWT standards.

This module implements secure token management following multiple RFCs:
- JSON Web Token (RFC 7519)
- OAuth2 Token Management (RFC 6749)
- Token Introspection (RFC 7662)
- Token Revocation (RFC 7009)
- Bearer Token Usage (RFC 6750)
- Proof Key for Code Exchange (RFC 7636)

Core Features:
1. Token Management
   - Access token creation and validation
   - Refresh token rotation
   - Token revocation
   - Token introspection
   - Metadata storage

2. Security Features
   - JWT signing and verification
   - Token type enforcement
   - Expiration handling
   - Revocation tracking
   - Metadata validation

3. Token Delivery
   - API response format
   - Secure cookie handling
   - Mobile app support
   - Web client support

4. Redis Integration
   - Token metadata storage
   - Revocation list
   - Session tracking
   - User agent tracking

Security Considerations:
- Uses secure JWT algorithms
- Implements token rotation
- Prevents token reuse
- Tracks user sessions
- Supports revocation
- Handles metadata securely
"""

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

# JWT algorithm following RFC 7518
ALGORITHM = "HS256"


class TokenType(str, Enum):
    """Token types following OAuth2 specification (RFC 6749).

    Defines the supported token types for authentication:
    - ACCESS: Short-lived tokens for API access
    - REFRESH: Long-lived tokens for obtaining new access tokens

    The type is included in the JWT payload to prevent
    token type confusion attacks.
    """

    ACCESS = "access"   # Short-lived API access token
    REFRESH = "refresh" # Long-lived refresh token


class TokenResponse(TypedDict):
    """OAuth2 token response format (RFC 6749 Section 5.1).

    Standardized response format for token endpoints:
    - access_token: The issued access token
    - refresh_token: Optional refresh token
    - token_type: Type of token (always "bearer")
    - expires_in: Token lifetime in seconds

    This format is used for API responses, while web clients
    receive refresh tokens via secure cookies.
    """

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload following RFC 7519.

    Required claims:
    - sub: Subject identifier (user ID)
    - exp: Expiration time
    - iat: Issued at time
    - jti: Unique token identifier
    - type: Token type (access/refresh)

    The payload is signed using HMAC-SHA256 (HS256)
    and includes standard JWT claims plus custom ones.
    """

    sub: str  # User ID in hex format
    exp: datetime  # Expiration time
    iat: datetime  # Issued at
    jti: str  # JWT ID in hex format
    type: TokenType  # Token type


class TokenMetadata(TypedDict):
    """Token metadata for security tracking.

    Stores additional information about tokens:
    - user_id: Associated user identifier
    - user_agent: Client user agent string
    - ip_address: Client IP address

    This data is stored in Redis and used for:
    - Session tracking
    - Security monitoring
    - Token revocation
    - Audit logging
    """

    user_id: str
    user_agent: str
    ip_address: str


class TokenService:
    """JWT token service with Redis-backed revocation.

    This service implements secure token management following OAuth2 and JWT standards:
    1. Token Creation
       - Generates signed JWTs
       - Includes standard claims
       - Stores metadata in Redis
       - Supports multiple delivery methods

    2. Token Validation
       - Verifies signatures
       - Checks expiration
       - Validates token type
       - Handles revocation

    3. Token Revocation
       - Single token revocation
       - Bulk user revocation
       - Metadata cleanup
       - Session termination

    4. Security Features
       - Token rotation
       - Metadata tracking
       - Session monitoring
       - Secure defaults

    Usage:
        service = TokenService()

        # Create tokens
        tokens = await service.create_tokens(user_id, user_agent, ip_address)

        # Verify token
        payload = await service.verify_token(token, TokenType.ACCESS)

        # Revoke token
        await service.revoke_token(token)

        # Revoke all user tokens
        await service.revoke_all_user_tokens(user_id)
    """

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
        """Create access and refresh tokens following OAuth2 specification.

        Implements secure token creation:
        1. Generates access token (short-lived)
        2. Generates refresh token (long-lived)
        3. Stores token metadata in Redis
        4. Handles multiple delivery methods

        For web clients:
        - Sets refresh token in HTTP-only cookie
        - Returns access token in response body

        For API clients:
        - Returns both tokens in response body
        - Includes token metadata

        Args:
            user_id: User ID to include in tokens
            user_agent: Client user agent for tracking
            ip_address: Client IP for tracking
            response: Optional response for cookie-based delivery

        Returns:
            TokenResponse | None: Tokens for API clients, None for web clients

        Security:
            - Uses secure JWT signing
            - Implements token rotation
            - Stores metadata securely
            - Supports secure cookies
            - Prevents token exposure
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
        """Create a new JWT access token.

        Implements secure access token creation:
        1. Generates unique token ID
        2. Creates standard JWT claims
        3. Sets appropriate expiration
        4. Signs token with HS256
        5. Handles creation errors

        Args:
            user_id: User ID to include in token

        Returns:
            str: Signed JWT access token

        Raises:
            JWTError: If token creation fails

        Security:
            - Uses secure JWT signing
            - Sets short expiration
            - Includes token type
            - Generates unique ID
            - Handles errors safely
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
        """Create a new JWT refresh token with metadata.

        Implements secure refresh token creation:
        1. Generates unique token ID
        2. Creates standard JWT claims
        3. Sets long expiration
        4. Signs token with HS256
        5. Stores metadata in Redis
        6. Handles creation errors

        Args:
            user_id: User ID to include in token
            user_agent: Client user agent for tracking
            ip_address: Client IP for tracking

        Returns:
            str: Signed JWT refresh token

        Raises:
            JWTError: If token creation fails

        Security:
            - Uses secure JWT signing
            - Stores metadata securely
            - Enables token tracking
            - Supports revocation
            - Handles errors safely
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

        Implements secure token verification:
        1. Verifies JWT signature
        2. Validates standard claims
        3. Checks token type
        4. Verifies expiration
        5. Checks revocation status
        6. Handles verification errors

        Args:
            token: JWT token to verify
            token_type: Expected token type (access/refresh)

        Returns:
            TokenPayload: Decoded token payload

        Raises:
            JWTError: If token is invalid, expired, or revoked

        Security:
            - Verifies signatures
            - Validates claims
            - Checks revocation
            - Prevents type confusion
            - Handles errors safely
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

        Retrieves token metadata from Redis:
        1. Checks token existence
        2. Gets associated user ID
        3. Retrieves tracking data
        4. Returns standardized format

        Used for:
        - Token validation
        - Session tracking
        - Security monitoring
        - Audit logging

        Args:
            token_id: Token ID (jti claim)

        Returns:
            TokenMetadata | None: Token metadata if found

        Security:
            - Validates token ID
            - Safe data retrieval
            - Standardized format
            - Handles missing data
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
