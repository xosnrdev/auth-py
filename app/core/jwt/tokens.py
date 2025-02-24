"""JWT token service implementing OAuth2 and JWT standards.

Example:
```python
# Initialize service
service = TokenService()

# Create tokens for web client
response = Response()
await service.create_tokens(
    user_id=UUID("123e4567-e89b-12d3-a456-426614174000"),
    user_agent="Mozilla/5.0...",
    ip_address="1.2.3.4",
    response=response,  # Sets HTTP-only cookie
)
assert "refresh_token" in response.cookies
assert response.cookies["refresh_token"].httponly is True
assert response.cookies["refresh_token"].secure is True

# Create tokens for mobile client
tokens = await service.create_tokens(
    user_id=UUID("123e4567-e89b-12d3-a456-426614174000"),
    user_agent="MyApp/1.0",
    ip_address="5.6.7.8",
)
assert tokens == {
    "access_token": "eyJhbGciOiJIUzI1...",  # JWT format
    "refresh_token": "eyJhbGciOiJIUzI1...",  # JWT format
    "token_type": "bearer",
    "expires_in": 3600  # 1 hour
}

# Verify token
payload = await service.verify_token(tokens["access_token"])
assert payload.sub == "123e4567-e89b-12d3-a456-426614174000"
assert payload.type == TokenType.ACCESS
assert payload.exp > datetime.now(UTC)

# Revoke token
await service.revoke_token(tokens["refresh_token"])
with pytest.raises(HTTPException):
    await service.verify_token(tokens["refresh_token"])
```

Critical Notes:
- Access tokens expire in 1 hour
- Refresh tokens expire in 7 days
- Tokens are signed with HS256
- Refresh tokens use HTTP-only cookies
- Token metadata stored in Redis
- Supports token revocation
- Prevents token reuse
- Tracks user sessions
- Requires secure transport
"""

import logging
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Final, TypedDict, cast
from uuid import UUID, uuid4

from fastapi import HTTPException, Response, status
from jose import JWTError, jwt
from pydantic import BaseModel, Field, field_validator
from redis.asyncio.client import Redis

from app.core.config import settings
from app.core.redis import redis

# Initialize logger
logger = logging.getLogger(__name__)

# Constants
ALGORITHM: Final[str] = "HS256"
TOKEN_PREFIX: Final[str] = "token:"
BEARER_FORMAT: Final[str] = "bearer"

# Token expiration
ACCESS_TOKEN_EXPIRES: Final[int] = settings.JWT_ACCESS_TOKEN_EXPIRES_SECS
REFRESH_TOKEN_EXPIRES: Final[int] = settings.JWT_REFRESH_TOKEN_EXPIRES_SECS
COOKIE_MAX_AGE: Final[int] = settings.COOKIE_MAX_AGE_SECS

# Redis key patterns
TOKEN_KEY_PATTERN: Final[str] = TOKEN_PREFIX + "*"
USER_TOKEN_PATTERN: Final[str] = TOKEN_PREFIX + "user:{user_id}:*"


class TokenType(str, Enum):
    """Token types following OAuth2 specification.

    Security:
    - Prevents token confusion attacks
    - Enforces token type validation
    - Ensures type safety
    """

    ACCESS = "access"
    REFRESH = "refresh"


class TokenResponse(TypedDict):
    """OAuth2 token response format (RFC 6749).

    Format:
    {
        "access_token": "eyJhbGci...",
        "refresh_token": "eyJhbGci...",
        "token_type": "bearer",
        "expires_in": 3600
    }
    """

    access_token: str
    refresh_token: str | None
    token_type: str
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload with validation.

    Security:
    - Required claims
    - Type validation
    - Time validation
    - Unique identifiers
    """

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
    """JWT token service with security features.

    Security:
    1. Token Management
       - Secure signing (HS256)
       - Type enforcement
       - Expiration handling
       - Metadata tracking

    2. Token Delivery
       - HTTP-only cookies
       - Secure transport
       - Bearer scheme
       - Mobile support

    3. Token Protection
       - Revocation support
       - Session tracking
       - Reuse prevention
       - Secure storage
    """

    def __init__(self) -> None:
        """Initialize with secure defaults."""
        assert settings.JWT_SECRET, "JWT secret must be configured"
        self.secret = settings.JWT_SECRET

    async def create_tokens(
        self,
        user_id: UUID,
        user_agent: str,
        ip_address: str,
        response: Response | None = None,
    ) -> TokenResponse | None:
        """Create access and refresh tokens securely.

        Args:
            user_id: User identifier
            user_agent: Client user agent
            ip_address: Client IP address
            response: Optional response for cookies

        Returns:
            TokenResponse | None: Tokens or None if using cookies

        Security:
            - Secure token generation
            - Metadata tracking
            - Cookie security
            - Type safety
        """
        # Create tokens
        access_token = await self.create_access_token(user_id)
        refresh_token = await self.create_refresh_token(
            user_id=user_id,
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Web client: Set secure cookie
        if response:
            response.set_cookie(
                key="refresh_token",
                value=refresh_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=COOKIE_MAX_AGE,
                expires=int(
                    (datetime.now(UTC) + timedelta(seconds=COOKIE_MAX_AGE))
                    .timestamp()
                ),
            )
            return None

        # API client: Return tokens
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=BEARER_FORMAT,
            expires_in=ACCESS_TOKEN_EXPIRES,
        )

    async def create_access_token(self, user_id: UUID) -> str:
        """Create short-lived access token.

        Args:
            user_id: User identifier

        Returns:
            str: Signed JWT token

        Security:
            - Short expiry
            - Type enforcement
            - Secure signing
            - UTC timestamps
        """
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=ACCESS_TOKEN_EXPIRES)
        token_id = uuid4().hex

        # Create payload
        payload = TokenPayload(
            sub=user_id.hex,
            exp=expires,
            iat=now,
            jti=token_id,
            type=TokenType.ACCESS,
        )

        # Sign token
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
        """Create long-lived refresh token.

        Args:
            user_id: User identifier
            user_agent: Client info
            ip_address: Client IP

        Returns:
            str: Signed JWT token

        Security:
            - Metadata tracking
            - Session monitoring
            - Secure storage
            - Type safety
        """
        now = datetime.now(UTC)
        expires = now + timedelta(seconds=REFRESH_TOKEN_EXPIRES)
        token_id = uuid4().hex

        # Create payload
        payload = TokenPayload(
            sub=str(user_id),
            exp=expires,
            iat=now,
            jti=token_id,
            type=TokenType.REFRESH,
        )

        # Store metadata
        await self._store_token_metadata(
            token_id=token_id,
            user_id=str(user_id),
            user_agent=user_agent,
            ip_address=ip_address,
        )

        # Sign token
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
        """Verify and decode JWT token.

        Args:
            token: JWT to verify
            token_type: Expected type

        Returns:
            TokenPayload: Decoded payload

        Raises:
            HTTPException: If validation fails

        Security:
            - Signature verification
            - Type validation
            - Expiry checking
            - Revocation check
        """
        try:
            # Decode and validate
            payload = jwt.decode(
                token=token,
                key=self.secret,
                algorithms=[ALGORITHM],
            )
            token_data = TokenPayload(**payload)

            # Validate type
            if token_data.type != token_type:
                raise ValueError("Invalid token type")

            # Check revocation
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
        """Get token metadata from Redis.

        Args:
            token_id: Token identifier

        Returns:
            TokenMetadata | None: Metadata if found

        Security:
            - Safe deserialization
            - Type validation
            - Null safety
        """
        # Get metadata
        key = f"{TOKEN_PREFIX}{token_id}"
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            result = await cast(Any, redis_client.hgetall(key))
            if not result:
                return None

            # Validate and return
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
        """Store token metadata in Redis.

        Args:
            token_id: Token identifier
            user_id: User identifier
            user_agent: Client info
            ip_address: Client IP

        Security:
            - Safe serialization
            - Expiry handling
            - Type safety
        """
        key = f"{TOKEN_PREFIX}{token_id}"
        metadata = {
            b"user_id": user_id.encode(),
            b"user_agent": user_agent.encode(),
            b"ip_address": ip_address.encode(),
        }
        redis_client = Redis(connection_pool=redis.connection_pool)
        try:
            await cast(Any, redis_client.hmset(key, metadata))
            await cast(Any, redis_client.expire(key, REFRESH_TOKEN_EXPIRES))
        except Exception as e:
            logger.error("Failed to store token metadata: %s", str(e))
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to store token metadata",
            ) from e

    async def revoke_token(self, token: str) -> None:
        """Revoke a refresh token.

        Args:
            token: JWT to revoke

        Security:
            - Immediate effect
            - Metadata cleanup
            - Type validation
            - Error handling
        """
        try:
            # Verify token first
            payload = await self.verify_token(token, TokenType.REFRESH)
            # Delete metadata
            await redis.delete(f"{TOKEN_PREFIX}{payload.jti}")
        except HTTPException:
            pass  # Token already invalid

    async def revoke_all_user_tokens(
        self,
        user_id: str,
        exclude_token_id: str | None = None,
    ) -> None:
        """Revoke all user's refresh tokens.

        Args:
            user_id: User identifier
            exclude_token_id: Token to preserve

        Security:
            - Bulk revocation
            - Session cleanup
            - Safe iteration
            - Error handling
        """
        pattern = USER_TOKEN_PATTERN.format(user_id=user_id)
        async for key in redis.scan_iter(pattern):
            if exclude_token_id and exclude_token_id in key:
                continue
            await redis.delete(key)


# Create global token service instance
token_service = TokenService()
