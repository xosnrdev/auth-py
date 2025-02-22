"""Apple OAuth2 provider implementation."""

from typing import Any, NotRequired, TypedDict

from fastapi import HTTPException, status

from app.core.oauth2.base import OAuth2Config, OAuth2Provider


class AppleNameInfo(TypedDict):
    """Apple name information structure."""

    firstName: NotRequired[str | None]
    lastName: NotRequired[str | None]


class AppleIDClaims(TypedDict):
    """Apple ID token claims."""

    sub: str  # Subject identifier
    email: str  # User's email
    email_verified: NotRequired[bool]  # Whether email is verified
    is_private_email: NotRequired[bool]  # Whether email is private relay
    name: NotRequired[AppleNameInfo | None]  # User's name (first login only)


class AppleOAuth2Config(OAuth2Config):
    """Apple OAuth2 provider configuration."""

    name: str = "apple"
    authorize_url: str = "https://appleid.apple.com/auth/authorize"
    token_url: str = "https://appleid.apple.com/auth/token"
    userinfo_url: str = "https://appleid.apple.com/auth/userinfo"  # Not used, info comes in id_token
    scope: list[str] = [
        "name",
        "email",
    ]


class AppleOAuth2Provider(OAuth2Provider):
    """Apple OAuth2 provider implementation."""

    async def get_user_info(self, token: dict[str, Any]) -> dict[str, Any]:
        """Get user info from Apple ID token.

        Apple doesn't provide a userinfo endpoint, all user info
        is included in the ID token from the token endpoint.

        Args:
            token: Access token response containing id_token

        Returns:
            dict[str, Any]: User info from Apple ID token

        Raises:
            HTTPException: If user info extraction fails
        """
        try:
            # Apple provides user info in the id_token
            id_token = token.get("id_token")
            if not id_token:
                raise ValueError("Missing ID token")

            # Parse user info from id_token claims
            # Note: In production, verify the JWT signature
            claims = self.client.parse_id_token(token, None)

            # Validate required fields
            if not isinstance(claims, dict):
                raise ValueError("Invalid claims format")

            try:
                validated_claims = AppleIDClaims(
                    sub=claims["sub"],
                    email=claims["email"],
                    email_verified=claims.get("email_verified", False),
                    is_private_email=claims.get("is_private_email", False),
                )
            except KeyError as e:
                raise ValueError(f"Missing required claim: {e}")

            # Get additional user info from token response
            # This is only provided on first login
            user_info = token.get("user", {})
            name_info = user_info.get("name", {})

            return {
                "provider": "apple",
                "sub": validated_claims["sub"],
                "email": validated_claims["email"],
                "email_verified": validated_claims["email_verified"],
                "name": name_info.get("firstName"),
                "family_name": name_info.get("lastName"),
                "is_private_email": validated_claims["is_private_email"],
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get user info from Apple: {str(e)}",
            ) from e
