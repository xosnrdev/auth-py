"""Token schemas for authentication responses."""

from datetime import datetime
from enum import Enum
from uuid import UUID

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field

from app.models.token import RevocationReason


class TokenType(str, Enum):
    """OAuth2 token types as per RFC 6749."""

    BEARER = "bearer"
    MAC = "mac"  # For future use


class ErrorCode(str, Enum):
    """OAuth2 error codes as per RFC 6749 Section 5.2."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    INVALID_SCOPE = "invalid_scope"


class TokenRevocationRequest(BaseModel):
    """Request model for token revocation as per RFC 7009."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "token_type_hint": "refresh_token",
                "reason": "user_request",
            }
        },
    )

    token: str = Field(
        description="The token to be revoked",
    )
    token_type_hint: str | None = Field(
        default=None,
        description="Hint about the type of the token ('refresh_token' or 'access_token')",
        examples=["refresh_token", "access_token"],
    )
    reason: RevocationReason = Field(
        default=RevocationReason.USER_REQUEST,
        description="Reason for token revocation",
    )


class TokenError(BaseModel):
    """OAuth2 token error response as per RFC 6749 Section 5.2."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "error": "invalid_request",
                "error_description": "Request was missing a required parameter",
                "error_uri": "https://example.com/docs/errors#invalid_request",
            }
        },
    )

    error: ErrorCode = Field(
        description="Error code as per RFC 6749",
    )
    error_description: str | None = Field(
        default=None,
        description="Human-readable error description",
    )
    error_uri: str | None = Field(
        default=None,
        description="URI to error documentation",
    )


class AccessTokenResponse(BaseModel):
    """Schema for access token response as per RFC 6749 Section 5.1.

    Note: Access tokens are stateless JWTs and are only returned in responses,
    never stored in the database.
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...",
                "token_type": "bearer",
                "expires_in": 1800,  # 30 minutes in seconds
                "scope": "read write",
            }
        },
    )

    access_token: str = Field(
        description="JWT access token",
    )
    token_type: TokenType = Field(
        default=TokenType.BEARER,
        description="Token type as per RFC 6749",
    )
    expires_in: int = Field(
        description="Number of seconds until the token expires",
    )
    scope: str | None = Field(
        default=None,
        description="Space-delimited list of scopes",
        examples=["read write", "admin"],
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
                "scope": "read write",
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
    - scope: Space-delimited list of granted scopes
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
                "scope": "read write",
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
    scope: str | None = Field(
        default=None,
        description="Space-delimited list of granted scopes",
    )
