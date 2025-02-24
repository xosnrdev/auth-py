"""Apple OAuth2 provider implementation following Sign in with Apple guidelines.

Example:
```python
# Initialize provider
provider = AppleOAuth2Provider(
    config=AppleOAuth2Config(
        client_id="com.example.app",
        client_secret="generated_jwt_token",  # Generated using team_id and key_id
        team_id="TEAM123456",                # Apple Developer Team ID
        key_id="KEY123456",                  # Private Key ID from Apple
        scope=["name", "email"]              # Default scopes
    )
)

# Get authorization URL
url, state = await provider.get_authorization_url(request)
# url: "https://appleid.apple.com/auth/authorize?..."
# state: "abc123..." (CSRF token)

# Exchange code for token
token = await provider.get_access_token(request)
assert token == {
    "access_token": "c6a...",           # Short-lived
    "token_type": "Bearer",
    "expires_in": 3600,
    "id_token": "eyJhbGci...",         # Contains user info
    "user": {                           # Only on first login
        "name": {
            "firstName": "John",
            "lastName": "Doe"
        }
    }
}

# Get user info (from id_token)
user = await provider.get_user_info(token)
assert user == {
    "provider": "apple",
    "sub": "001234.abcd...",        # Stable user ID
    "email": "xyz@privaterelay.appleid.com",
    "email_verified": True,         # Always true
    "is_private_email": True,       # Email relay status
    "name": "John",                 # Only on first login
    "family_name": "Doe"           # Only on first login
}
```

Critical Notes:
- JWT client_secret required (see Apple docs)
- User info comes from id_token, not userinfo endpoint
- Name only provided on first login
- Email can be private relay
- Stable user ID across apps
- HTTPS and PKCE required
- Token expiry < 1 hour
- No refresh tokens
"""

from typing import Any, Final, Literal, NotRequired, TypedDict
from urllib.parse import urlparse

from fastapi import HTTPException, status
from pydantic import Field, field_validator

from app.core.oauth2.base import OAuth2Config, OAuth2Provider, UserInfo

# Constants for validation
MIN_TEAM_ID_LENGTH: Final[int] = 10
MIN_KEY_ID_LENGTH: Final[int] = 10
APPLE_DOMAIN: Final[str] = "appleid.apple.com"
REQUIRED_SCOPES: Final[tuple[str, ...]] = ("name", "email")


class AppleNameInfo(TypedDict):
    """Apple name information structure.

    Only provided on first login or when scope=name.
    """

    firstName: NotRequired[str | None]  # Given name
    lastName: NotRequired[str | None]  # Family name


class AppleIDClaims(TypedDict):
    """Apple ID token claims following OpenID spec.

    Required claims:
    - sub: Unique stable user ID
    - email: User's email (can be relay)
    - email_verified: Always true for Apple
    - is_private_email: True if relay email
    """

    iss: str  # Issuer (must be https://appleid.apple.com)
    sub: str  # Subject identifier (unique user ID)
    aud: str  # Audience (your client_id)
    exp: int  # Expiration time
    iat: int  # Issued at time
    email: str  # User's email address
    email_verified: NotRequired[bool]  # Always true for Apple
    is_private_email: NotRequired[bool]  # True if relay email
    nonce: NotRequired[str | None]  # If provided in request
    nonce_supported: NotRequired[bool]  # If nonce supported
    name: NotRequired[AppleNameInfo | None]  # User's name (first login)
    auth_time: NotRequired[int | None]  # Authentication time


class AppleOAuth2Config(OAuth2Config):
    """Apple OAuth2 provider configuration with validation.

    Security requirements:
    - Valid team_id and key_id
    - HTTPS endpoints
    - Required scopes
    - JWT client_secret
    """

    name: Literal["apple"] = "apple"
    authorize_url: Literal["https://appleid.apple.com/auth/authorize"] = "https://appleid.apple.com/auth/authorize"
    token_url: Literal["https://appleid.apple.com/auth/token"] = "https://appleid.apple.com/auth/token"
    userinfo_url: Literal["https://appleid.apple.com/auth/userinfo"] = "https://appleid.apple.com/auth/userinfo"
    scope: list[str] = Field(default_factory=lambda: list(REQUIRED_SCOPES))
    team_id: str = Field(min_length=MIN_TEAM_ID_LENGTH, pattern=r"^[A-Z0-9]+$")
    key_id: str = Field(min_length=MIN_KEY_ID_LENGTH, pattern=r"^[A-Z0-9]+$")

    @field_validator("scope")
    @classmethod
    def validate_scope(cls, v: list[str]) -> list[str]:
        """Validate required Apple scopes."""
        missing = set(REQUIRED_SCOPES) - set(v)
        if missing:
            raise ValueError(f"Required scopes missing: {missing}")
        return v

    @field_validator("authorize_url", "token_url", "userinfo_url")
    @classmethod
    def validate_apple_urls(cls, v: str) -> str:
        """Ensure URLs are valid Apple endpoints."""
        parsed = urlparse(v)
        if parsed.scheme != "https" or parsed.netloc != APPLE_DOMAIN:
            raise ValueError(f"Invalid Apple URL: {v}")
        return v


class AppleOAuth2Provider(OAuth2Provider):
    """Apple OAuth2 provider with ID token validation.

    Security features:
    1. JWT signature verification
    2. Claims validation
    3. Timestamp validation
    4. Audience validation
    5. Issuer validation
    """

    async def get_user_info(self, token: dict[str, Any]) -> UserInfo:
        """Extract user info from Apple ID token.

        Apple doesn't provide a userinfo endpoint, all user info
        is included in the ID token from the token endpoint.
        Name info is only provided on first login.

        Args:
            token: Access token response with id_token

        Returns:
            UserInfo: Validated user info

        Raises:
            HTTPException: If validation fails
            ValueError: If token format invalid
        """
        try:
            # Validate token format
            id_token = token.get("id_token")
            if not id_token:
                raise ValueError("Missing ID token")

            # Parse and validate claims
            claims = self.client.parse_id_token(token, None)
            if not isinstance(claims, dict):
                raise ValueError("Invalid claims format")

            # Validate required claims
            try:
                validated_claims = AppleIDClaims(
                    iss=claims["iss"],
                    sub=claims["sub"],
                    aud=claims["aud"],
                    exp=claims["exp"],
                    iat=claims["iat"],
                    email=claims["email"],
                    email_verified=claims.get("email_verified", True),  # Always true
                    is_private_email=claims.get("is_private_email", False),
                    nonce=str(claims["nonce"]) if claims.get("nonce") else None,
                    nonce_supported=bool(claims.get("nonce_supported", False)),
                    auth_time=int(claims["auth_time"]) if claims.get("auth_time") else None,
                )
            except (KeyError, ValueError, TypeError) as e:
                raise ValueError(f"Invalid claim format: {e}")

            # Validate issuer
            if validated_claims["iss"] != f"https://{APPLE_DOMAIN}":
                raise ValueError("Invalid token issuer")

            # Validate audience
            if validated_claims["aud"] != self.config.client_id:
                raise ValueError("Invalid token audience")

            # Get name info (only on first login)
            user_info = token.get("user", {})
            name_info = user_info.get("name", {})

            # Convert to common format
            return UserInfo(
                provider="apple",
                sub=validated_claims["sub"],
                email=validated_claims["email"],
                email_verified=validated_claims["email_verified"],
                name=name_info.get("firstName"),
                family_name=name_info.get("lastName"),
                is_private_email=validated_claims["is_private_email"],
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get user info from Apple: {str(e)}",
            ) from e
