"""Google OAuth2 integration with user info validation.

Example:
```python
# Initialize provider
provider = GoogleOAuth2Provider(
    config=GoogleOAuth2Config(
        client_id="your-client-id",
        client_secret="your-client-secret",
        redirect_uri="https://your-app/oauth/google"
    )
)

# Get user info from token
user_info = await provider.get_user_info({
    "access_token": "ya29.a0AfB_...",
    "token_type": "Bearer",
    "expires_in": 3599
})
assert user_info == UserInfo(
    provider="google",
    sub="12345...",           # Unique Google ID
    email="user@gmail.com",   # Verified email
    email_verified=True,      # Always verify
    name="John Doe",          # Optional full name
    picture="https://...",    # Optional avatar URL
    locale="en"               # Optional language
)
```

Critical Notes:
- Requires Google OAuth2 credentials
- Email scope required for login
- Email must be verified
- Sub (Google ID) required
- HTTPS endpoints only
- Token validation required
- Rate limiting may apply
- Handles only Bearer tokens
"""

from typing import Any, Final, Literal, NotRequired, TypedDict, cast
from urllib.parse import urlparse

from fastapi import HTTPException, status
from pydantic import EmailStr, HttpUrl

from app.core.oauth2.base import OAuth2Config, OAuth2Provider, UserInfo

# Constants
PROVIDER_NAME: Final[str] = "google"
AUTHORIZE_URL: Final[str] = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL: Final[str] = "https://oauth2.googleapis.com/token"
USERINFO_URL: Final[str] = "https://www.googleapis.com/oauth2/v3/userinfo"
REQUIRED_SCOPES: Final[tuple[str, ...]] = ("openid", "email", "profile")
MAX_RETRIES: Final[int] = 3
TIMEOUT_SECONDS: Final[int] = 10


class GoogleUserInfo(TypedDict):
    """Google user info response type.

    All fields are validated according to Google's OAuth2 specification.
    """

    sub: str  # Unique Google ID
    email: str  # Primary email
    email_verified: NotRequired[bool]  # Verification status
    name: NotRequired[str | None]  # Full name
    given_name: NotRequired[str | None]  # First name
    family_name: NotRequired[str | None]  # Last name
    picture: NotRequired[str | None]  # Avatar URL
    locale: NotRequired[str | None]  # Language


class GoogleOAuth2Token(TypedDict):
    """Google OAuth2 token response type."""

    access_token: str
    token_type: Literal["Bearer"]
    expires_in: int


class GoogleOAuth2Config(OAuth2Config):
    """Google OAuth2 configuration with enhanced validation."""

    name: str = PROVIDER_NAME
    authorize_url: str = AUTHORIZE_URL
    token_url: str = TOKEN_URL
    userinfo_url: str = USERINFO_URL
    scope: list[str] = list(REQUIRED_SCOPES)

    def __init__(self, **data: Any) -> None:
        """Initialize and validate config.

        Raises:
            ValueError: If URLs are not HTTPS or required scopes are missing
            AssertionError: If configuration is invalid
        """
        super().__init__(**data)

        # Validate credentials
        assert self.client_id and len(self.client_id) > 20, "Invalid client_id"
        assert self.client_secret and len(self.client_secret) > 20, "Invalid client_secret"

        # Validate HTTPS URLs
        for url in [self.authorize_url, self.token_url, self.userinfo_url]:
            parsed = urlparse(url)
            if parsed.scheme != "https":
                raise ValueError(f"OAuth2 endpoint must use HTTPS: {url}")

        # Validate required scopes
        missing = set(REQUIRED_SCOPES) - set(self.scope)
        if missing:
            raise ValueError(f"Required scopes missing: {missing}")


class GoogleOAuth2Provider(OAuth2Provider):
    """Google OAuth2 implementation with enhanced security."""

    async def get_user_info(self, token: dict[str, Any]) -> UserInfo:
        """Get and validate Google user info.

        Args:
            token: OAuth2 access token response

        Returns:
            Validated user info

        Raises:
            HTTPException: If validation fails or rate limit exceeded
            ValueError: If token format is invalid
            AssertionError: If response validation fails
        """
        # Validate token format
        try:
            oauth_token = cast(GoogleOAuth2Token, token)
            assert oauth_token["token_type"] == "Bearer", "Only Bearer tokens supported"
            assert oauth_token["expires_in"] > 0, "Token expired"
        except (KeyError, AssertionError) as e:
            raise ValueError(f"Invalid token format: {e}")

        try:
            # Get user info with retry and timeout
            resp = await self.client.get(
                self.config.userinfo_url,
                token=token,
                timeout=TIMEOUT_SECONDS,
                max_retries=MAX_RETRIES,
            )
            resp.raise_for_status()
            data = resp.json()

            # Validate response format
            if not isinstance(data, dict):
                raise ValueError("Invalid response format")

            # Validate and extract fields
            try:
                info = GoogleUserInfo(
                    sub=str(data["sub"]),
                    email=EmailStr(data["email"]).lower(),
                    email_verified=bool(data.get("email_verified", False)),
                    name=str(data["name"]) if data.get("name") else None,
                    given_name=str(data["given_name"]) if data.get("given_name") else None,
                    family_name=str(data["family_name"]) if data.get("family_name") else None,
                    picture=str(HttpUrl(data["picture"])) if data.get("picture") else None,
                    locale=str(data["locale"]) if data.get("locale") else None,
                )
            except (KeyError, ValueError) as e:
                raise ValueError(f"Invalid field format: {e}")

            # Validate email verification
            if not info["email_verified"]:
                raise ValueError("Email must be verified")

            # Convert to common format with validation
            return UserInfo(
                provider=PROVIDER_NAME,
                sub=info["sub"],
                email=info["email"],
                email_verified=info["email_verified"],
                name=info.get("name"),
                family_name=info.get("family_name"),
                picture=info.get("picture"),
                locale=info.get("locale"),
            )

        except Exception as e:
            if "429" in str(e):
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Google API rate limit exceeded",
                ) from e
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get user info from Google: {str(e)}",
            ) from e
