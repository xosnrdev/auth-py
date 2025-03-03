"""JWT token validation schemas"""

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, PositiveInt, ValidationInfo, field_validator


class TokenType(StrEnum):
    """Token types following OAuth2 specification."""

    ACCESS = "access"
    REFRESH = "refresh"


class TokenResponse(BaseModel):
    """OAuth2 token response format (RFC 6749)."""

    access_token: str = Field(description="JWT access token")
    refresh_token: str | None = Field(default=None, description="JWT refresh token")
    token_type: str = Field(
        default="bearer", pattern="^bearer$", description="Token type (always 'bearer')"
    )
    expires_in: PositiveInt = Field(description="Token expiration time in seconds")


class TokenMetadata(BaseModel):
    """Token metadata for security tracking.

    Used for:
    - Session management
    - Security monitoring
    - Audit logging
    - Token revocation
    """

    user_id: str = Field(
        min_length=32,
        max_length=36,
        description="User ID in UUID format",
        pattern="^[0-9a-f]{32}$|^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    user_agent: str = Field(description="User agent string from request")
    ip_address: str = Field(
        description="Client IP address",
        pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$",
    )


class TokenPayload(BaseModel):
    """JWT token payload with validation.

    This model validates the JWT payload according to RFC 7519.
    Fields:
        sub: Subject identifier (user ID)
        exp: Expiration time
        iat: Issued at time
        jti: JWT ID (unique identifier)
        type: Token type (access or refresh)
    """

    sub: str = Field(
        min_length=32,
        max_length=36,
        description="Subject identifier (user ID in UUID format)",
        pattern="^[0-9a-f]{32}$|^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )
    exp: datetime = Field(description="Token expiration timestamp (UTC)")
    iat: datetime = Field(description="Token issued at timestamp (UTC)")
    jti: str = Field(
        min_length=32,
        max_length=36,
        description="Unique token identifier",
        pattern="^[0-9a-f]{32}$",
    )
    type: TokenType = Field(description="Token type (access or refresh)")

    @field_validator("exp", "iat")
    @classmethod
    def validate_timestamps(cls, v: datetime) -> datetime:
        """Ensure timestamps are UTC."""
        assert v.tzinfo is not None, "Timestamp must be timezone-aware"
        return v.astimezone(UTC)

    @field_validator("exp")
    @classmethod
    def validate_expiration(cls, v: datetime, info: ValidationInfo) -> datetime:
        """Ensure expiration is after issued at time."""
        if hasattr(info, "data") and "iat" in info.data and v <= info.data["iat"]:
            raise ValueError("Expiration time must be after issued at time")
        return v


class TokenCreate(BaseModel):
    """Schema for creating a new token.

    This model represents the data needed to create a new token.
    It is used internally by the token service and not exposed in the API.
    """

    user_id: UUID = Field(description="User ID for whom the token is being created")
    user_agent: str = Field(description="User agent string from request")
    ip_address: str = Field(
        description="Client IP address",
        pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$",
    )
    token_type: TokenType = Field(description="Type of token to create")
    expires_in: PositiveInt | None = Field(
        default=None,
        description="Token expiration time in seconds. If not provided, defaults will be used.",
    )

    model_config = {
        "json_schema_extra": {
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "ip_address": "192.168.1.1",
                "token_type": "access",
                "expires_in": 3600,
            }
        }
    }


__all__ = [
    "TokenType",
    "TokenResponse",
    "TokenMetadata",
    "TokenPayload",
    "TokenCreate",
]
