"""JWT token validation schemas with examples.

Example:
```python
# Login response
token = TokenResponse(
    access_token="eyJhbGciOiJIUzI1NiI...",  # JWT token
    refresh_token="eyJhbGciOiJIUzI1NiI...",  # Optional
    token_type="bearer",
    expires_in=3600  # Seconds
)

# Token introspection (RFC 7662)
info = TokenIntrospectionResponse(
    active=True,
    token_type="access",
    exp=1684081234,  # Unix timestamp
    sub="user-123"   # User ID
)

# OAuth2 metadata
meta = TokenMetadataResponse(
    issuer="https://auth.example.com",
    response_types_supported=["code"],
    grant_types_supported=["authorization_code"],
    code_challenge_methods_supported=["S256"]
)
```

Critical Notes:
- All timestamps are Unix epoch seconds
- Token types: "access" or "refresh" only
- Bearer tokens only (JWT format)
- PKCE S256 required for auth code
- All URLs must be HTTPS
"""

from typing import Final, Literal
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Constants
TOKEN_TYPE_BEARER: Final[str] = "bearer"
TOKEN_TYPES: Final[tuple[str, str]] = ("access", "refresh")
DEFAULT_EXPIRES_IN: Final[int] = 3600
MIN_TOKEN_LENGTH: Final[int] = 32
MAX_TOKEN_LENGTH: Final[int] = 512


class TokenResponse(BaseModel):
    """Authentication token response."""

    model_config = ConfigDict(populate_by_name=True)

    access_token: str = Field(
        min_length=MIN_TOKEN_LENGTH,
        max_length=MAX_TOKEN_LENGTH,
        examples=["eyJhbGciOiJIUzI1NiI..."],
    )
    refresh_token: str | None = Field(
        default=None,
        min_length=MIN_TOKEN_LENGTH,
        max_length=MAX_TOKEN_LENGTH,
        examples=["eyJhbGciOiJIUzI1NiI..."],
    )
    token_type: str = Field(
        default=TOKEN_TYPE_BEARER,
        pattern="^bearer$",
        examples=["bearer"],
    )
    expires_in: int = Field(
        default=DEFAULT_EXPIRES_IN,
        gt=0,
        examples=[3600],
    )


class TokenIntrospectionResponse(BaseModel):
    """Token validation status and claims."""

    model_config = ConfigDict(populate_by_name=True)

    active: bool = Field(examples=[True])
    scope: str | None = Field(
        default=None,
        pattern="^[a-z0-9 ]+$",
        examples=["read write"],
    )
    client_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        examples=["example-client"],
    )
    username: str | None = Field(
        default=None,
        examples=["user@example.com"],
    )
    token_type: Literal["access", "refresh"] | None = Field(
        default=None,
        examples=["access"],
    )
    exp: int | None = Field(
        default=None,
        gt=0,
        examples=[1684081234],
    )
    iat: int | None = Field(
        default=None,
        gt=0,
        examples=[1684077634],
    )
    nbf: int | None = Field(
        default=None,
        gt=0,
        examples=[1684077634],
    )
    sub: str | None = Field(
        default=None,
        min_length=1,
        examples=["user-123"],
    )
    aud: list[str] | None = Field(
        default=None,
        examples=[["example-resource"]],
    )
    iss: str | None = Field(
        default=None,
        min_length=1,
        examples=["https://auth.example.com"],
    )
    jti: str | None = Field(
        default=None,
        min_length=1,
        examples=["token-123"],
    )

    @field_validator("iss")
    @classmethod
    def validate_issuer_url(cls, v: str | None) -> str | None:
        """Ensure issuer URL is HTTPS."""
        if v is None:
            return None
        parsed = urlparse(v)
        assert parsed.scheme == "https", "Issuer URL must use HTTPS"
        assert parsed.netloc, "Invalid issuer URL"
        return v


class TokenMetadataResponse(BaseModel):
    """OAuth2 authorization server metadata."""

    model_config = ConfigDict(populate_by_name=True)

    issuer: str = Field(examples=["https://auth.example.com"])
    authorization_endpoint: str | None = Field(
        default=None,
        examples=["https://auth.example.com/oauth/authorize"],
    )
    token_endpoint: str | None = Field(
        default=None,
        examples=["https://auth.example.com/oauth/token"],
    )
    jwks_uri: str | None = Field(
        default=None,
        examples=["https://auth.example.com/.well-known/jwks.json"],
    )
    response_types_supported: list[str] = Field(
        default_factory=lambda: ["code"],
        examples=[["code"]],
    )
    grant_types_supported: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"],
        examples=[["authorization_code", "refresh_token"]],
    )
    token_endpoint_auth_methods_supported: list[str] = Field(
        default_factory=lambda: ["client_secret_post"],
        examples=[["client_secret_post"]],
    )
    code_challenge_methods_supported: list[str] = Field(
        default_factory=lambda: ["S256"],
        examples=[["S256"]],
    )

    @field_validator("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")
    @classmethod
    def validate_https_url(cls, v: str | None) -> str | None:
        """Ensure all URLs use HTTPS."""
        if v is None:
            return None
        parsed = urlparse(v)
        assert parsed.scheme == "https", "URL must use HTTPS"
        assert parsed.netloc, "Invalid URL"
        return v
