"""Token schemas for request and response models."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class TokenIntrospectionResponse(BaseModel):
    """Token introspection response following RFC 7662."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "active": True,
                "scope": "read write",
                "client_id": "example-client",
                "username": "user@example.com",
                "token_type": "access",
                "exp": 1684081234,
                "iat": 1684077634,
                "nbf": 1684077634,
                "sub": "user-id-hex",
                "aud": ["example-resource"],
                "iss": "https://auth.example.com",
                "jti": "token-id-hex",
            }
        },
    )

    active: bool
    scope: str | None = None
    client_id: str | None = None
    username: str | None = None
    token_type: Literal["access", "refresh"] | None = None
    exp: int | None = None
    iat: int | None = None
    nbf: int | None = None
    sub: str | None = None
    aud: list[str] | None = None
    iss: str | None = None
    jti: str | None = None


class TokenMetadataResponse(BaseModel):
    """Token metadata response for client applications."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                "token_endpoint": "https://auth.example.com/oauth/token",
                "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
                "code_challenge_methods_supported": ["S256"],
            }
        },
    )

    issuer: str
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    jwks_uri: str | None = None
    response_types_supported: list[str]
    grant_types_supported: list[str]
    token_endpoint_auth_methods_supported: list[str]
    code_challenge_methods_supported: list[str]
