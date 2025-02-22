"""Token schemas for authentication responses."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.base import BaseSchema


class TokenBase(BaseModel):
    """Base schema for token data."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "token_type": "bearer",
                "expires_at": "2024-02-21T22:45:54.669903+00:00",
            }
        },
    )

    access_token: str = Field(
        description="JWT access token",
    )
    refresh_token: str = Field(
        description="JWT refresh token",
    )
    token_type: str = Field(
        default="bearer",
        description="Token type (always 'bearer')",
    )
    expires_at: datetime = Field(
        description="Token expiration timestamp",
    )


class TokenResponse(TokenBase, BaseSchema):
    """Schema for token responses."""

    jti: UUID = Field(
        description="JWT ID (user ID)",
    )
    revoked: bool = Field(
        description="Whether the token has been revoked",
    )


class TokenPayload(BaseModel):
    """Schema for JWT token payload."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "sub": "123e4567-e89b-12d3-a456-426614174000",
                "exp": 1582495154,
                "iat": 1582491554,
                "jti": "123e4567-e89b-12d3-a456-426614174000",
                "type": "access",
            }
        },
    )

    sub: UUID = Field(
        description="Subject (user ID)",
    )
    exp: int = Field(
        description="Expiration timestamp",
    )
    iat: int = Field(
        description="Issued at timestamp",
    )
    jti: UUID = Field(
        description="JWT ID",
    )
    type: str = Field(
        description="Token type ('access' or 'refresh')",
    )
