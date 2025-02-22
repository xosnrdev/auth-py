"""Token schemas for authentication responses."""

from datetime import datetime
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field


class AccessTokenResponse(BaseModel):
    """Schema for access token response.

    Note: Access tokens are stateless JWTs and are only returned in responses,
    never stored in the database.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800,  # 30 minutes in seconds
            }
        },
    )

    access_token: str = Field(
        description="JWT access token",
    )
    token_type: str = Field(
        default="bearer",
        description="Token type (always 'bearer')",
    )
    expires_in: int = Field(
        description="Number of seconds until the token expires",
    )


class RefreshTokenResponse(BaseModel):
    """Schema for refresh token response."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "expires_at": "2024-03-21T22:45:54.669903+00:00",
            }
        },
    )

    refresh_token: str = Field(
        description="JWT refresh token",
    )
    expires_at: datetime = Field(
        description="Refresh token expiration timestamp",
    )


class TokenResponse(AccessTokenResponse, RefreshTokenResponse):
    """Combined schema for login response including both tokens."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "expires_at": "2024-03-21T22:45:54.669903+00:00",
            }
        },
    )


class TokenPayload(BaseModel):
    """Schema for JWT token payload following RFC 7519 standards.

    Registered claims:
    - iss (Issuer): Identifies principal that issued the JWT
    - sub (Subject): Identifies the subject of the JWT
    - aud (Audience): Identifies the recipients the JWT is intended for
    - exp (Expiration Time): Identifies the expiration time after which the JWT must not be accepted
    - nbf (Not Before): Identifies the time before which the JWT must not be accepted
    - iat (Issued At): Identifies the time at which the JWT was issued
    - jti (JWT ID): Provides a unique identifier for the JWT

    Custom claims:
    - type: Identifies the token type ("access" or "refresh")
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "iss": "https://auth.example.com",
                "sub": "123e4567-e89b-12d3-a456-426614174000",
                "aud": ["https://api.example.com"],
                "exp": 1582495154,
                "nbf": 1582491554,
                "iat": 1582491554,
                "jti": "123e4567-e89b-12d3-a456-426614174000",
                "type": "access",
            }
        },
    )

    # RFC 7519 registered claims
    iss: AnyHttpUrl = Field(
        description="Issuer - identifies principal that issued the JWT",
    )
    sub: UUID = Field(
        description="Subject - identifies the subject of the JWT",
    )
    aud: list[str] = Field(
        description="Audience - identifies the recipients the JWT is intended for",
    )
    exp: int = Field(
        description="Expiration time - identifies when the JWT expires",
    )
    nbf: int = Field(
        description="Not before time - identifies when the JWT becomes valid",
    )
    iat: int = Field(
        description="Issued at time - identifies when the JWT was issued",
    )
    jti: UUID = Field(
        description="JWT ID - provides a unique identifier for the JWT",
    )

    # Custom claims
    type: str = Field(
        description="Token type ('access' or 'refresh')",
    )
