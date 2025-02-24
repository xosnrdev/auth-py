"""OAuth2 base provider implementation following RFC 6749 and RFC 7636 (PKCE).

Example:
```python
# Initialize provider
provider = OAuth2Provider(
    config=OAuth2Config(
        name="example",
        client_id="client_123",
        client_secret="secret_456",
        authorize_url="https://auth.example.com/authorize",
        token_url="https://auth.example.com/token",
        userinfo_url="https://api.example.com/userinfo",
        scope=["openid", "email", "profile"]
    )
)

# Get authorization URL
url, state = await provider.get_authorization_url(request)
# url: "https://auth.example.com/authorize?..."
# state: "abc123..." (CSRF token)

# Exchange code for token
token = await provider.get_access_token(request)
assert token == {
    "access_token": "ya29.a0AfB_...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "1//0eXy...",  # Optional
    "id_token": "eyJhbGci..."       # Optional
}

# Get user info
user = await provider.get_user_info(token)
assert user == {
    "provider": "example",
    "sub": "user_123",           # Unique ID
    "email": "user@example.com", # Primary email
    "email_verified": True,      # Must be verified
    "name": "John Doe",          # Optional
    "picture": "https://...",    # Optional
    "locale": "en"               # Optional
}
```

Critical Notes:
- HTTPS required for all endpoints
- PKCE (RFC 7636) enforced for security
- State parameter prevents CSRF
- Access tokens are short-lived
- Email verification required
- Rate limiting recommended
- Session storage required
- Refresh tokens optional
"""

import secrets
from abc import ABC, abstractmethod
from typing import Any, Final, NotRequired, TypedDict
from urllib.parse import urlparse

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator

# Constants for validation
MIN_CODE_VERIFIER_LENGTH: Final[int] = 64
MIN_STATE_LENGTH: Final[int] = 32
MIN_CLIENT_ID_LENGTH: Final[int] = 20
MIN_CLIENT_SECRET_LENGTH: Final[int] = 20
MAX_SCOPE_LENGTH: Final[int] = 1024


class UserInfo(TypedDict):
    """Common user info structure returned by OAuth2 providers.

    All fields follow OpenID Connect Core 1.0 specifications.
    """

    provider: str  # Provider name (e.g., "google", "apple")
    sub: str  # Subject identifier (unique user ID)
    email: str  # Primary email address
    email_verified: bool  # Email verification status
    name: NotRequired[str | None]  # Full name or first name
    family_name: NotRequired[str | None]  # Last name
    picture: NotRequired[str | None]  # Profile picture URL
    locale: NotRequired[str | None]  # Language preference
    is_private_email: NotRequired[bool]  # Private relay (Apple)


class OAuth2Config(BaseModel):
    """OAuth2 provider configuration with validation.

    Enforces security requirements:
    - HTTPS URLs
    - Minimum credential lengths
    - Required scopes
    - Immutable settings
    """

    model_config = ConfigDict(
        frozen=True,  # Prevent modification after creation
    )

    name: str = Field(min_length=1, max_length=50)
    client_id: str = Field(min_length=MIN_CLIENT_ID_LENGTH)
    client_secret: str = Field(min_length=MIN_CLIENT_SECRET_LENGTH)
    authorize_url: str = Field(pattern=r"^https://.*")
    token_url: str = Field(pattern=r"^https://.*")
    userinfo_url: str = Field(pattern=r"^https://.*")
    scope: list[str] = Field(min_length=1)

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: list[str]) -> list[str]:
        """Validate OAuth2 scopes."""
        assert v, "At least one scope required"
        scope_str = " ".join(v)
        assert len(scope_str) <= MAX_SCOPE_LENGTH, f"Combined scope exceeds {MAX_SCOPE_LENGTH} chars"
        return v

    @field_validator("authorize_url", "token_url", "userinfo_url")
    @classmethod
    def validate_urls(cls, v: str) -> str:
        """Ensure URLs use HTTPS and are valid."""
        parsed = urlparse(v)
        assert parsed.scheme == "https", "OAuth2 endpoints must use HTTPS"
        assert parsed.netloc, "Invalid URL format"
        return v


class TokenResponse(TypedDict):
    """OAuth2 token response following RFC 6749.

    Required fields:
    - access_token: The token for API access
    - token_type: Must be "Bearer"
    - expires_in: Seconds until expiry

    Optional fields:
    - refresh_token: For token refresh
    - id_token: JWT for OpenID Connect
    """

    access_token: str  # OAuth2 access token
    token_type: str  # Must be "Bearer"
    expires_in: int  # Seconds until expiry
    refresh_token: str | None  # Optional refresh token
    id_token: str | None  # Optional OpenID Connect token


class OAuth2Provider(ABC):
    """Base OAuth2 provider with PKCE support.

    Security features:
    1. PKCE challenge (RFC 7636)
    2. State parameter (CSRF)
    3. HTTPS enforcement
    4. Token validation
    5. Error handling
    """

    def __init__(self, config: OAuth2Config) -> None:
        """Initialize OAuth2 provider with validation.

        Args:
            config: Provider configuration

        Raises:
            ValueError: If configuration is invalid
        """
        self.config = config
        self.oauth = OAuth()  # type: ignore[no-untyped-call]
        self.client = self.oauth.register(
            name=config.name,
            client_id=config.client_id,
            client_secret=config.client_secret,
            authorize_url=config.authorize_url,
            authorize_params=None,
            token_url=config.token_url,
            token_endpoint_auth_method="client_secret_post",
            userinfo_url=config.userinfo_url,
            client_kwargs={
                "scope": " ".join(config.scope),
                "code_challenge_method": "S256",  # PKCE required
            },
        )

    async def get_authorization_url(self, request: Request) -> tuple[str, str]:
        """Get authorization URL with PKCE and state.

        Args:
            request: FastAPI request object

        Returns:
            tuple[str, str]: Authorization URL and state

        Raises:
            HTTPException: If URL generation fails
        """
        try:
            # Generate PKCE verifier (RFC 7636)
            code_verifier = secrets.token_urlsafe(MIN_CODE_VERIFIER_LENGTH)
            request.session["code_verifier"] = code_verifier

            # Generate state for CSRF protection
            state = secrets.token_urlsafe(MIN_STATE_LENGTH)
            request.session["oauth_state"] = state

            # Get authorization URL
            url = await self.client.authorize_redirect(
                request,
                state=state,
                code_verifier=code_verifier,
            )
            return str(url), state
        except OAuthError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to generate authorization URL: {str(e)}",
            ) from e

    async def get_access_token(self, request: Request) -> TokenResponse:
        """Exchange code for tokens with PKCE verification.

        Args:
            request: FastAPI request object

        Returns:
            TokenResponse: Access token response

        Raises:
            HTTPException: If token exchange fails
        """
        try:
            # Verify state parameter (CSRF)
            state = request.query_params.get("state")
            stored_state = request.session.pop("oauth_state", None)
            if not state or not stored_state or state != stored_state:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid state parameter",
                )

            # Verify PKCE code
            code_verifier = request.session.pop("code_verifier", None)
            if not code_verifier:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Missing PKCE code verifier",
                )

            # Exchange code for token
            token: TokenResponse = await self.client.authorize_access_token(
                request,
                code_verifier=code_verifier,
            )
            return token
        except OAuthError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get access token: {str(e)}",
            ) from e

    @abstractmethod
    async def get_user_info(self, token: dict[str, Any]) -> UserInfo:
        """Get user info from provider (abstract).

        Must be implemented by providers to:
        1. Validate token format
        2. Call userinfo endpoint
        3. Validate response
        4. Convert to UserInfo format
        5. Verify email status

        Args:
            token: Access token response

        Returns:
            UserInfo: Validated user info

        Raises:
            HTTPException: If validation fails
            ValueError: If token format invalid
        """
        raise NotImplementedError
