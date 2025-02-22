"""Google OAuth2 provider implementation."""

from typing import Any, NotRequired, TypedDict

from fastapi import HTTPException, status

from app.core.oauth2.base import OAuth2Config, OAuth2Provider, UserInfo


class GoogleUserInfo(TypedDict):
    """Google userinfo response."""

    sub: str  # Subject identifier
    email: str  # User's email
    email_verified: NotRequired[bool]  # Whether email is verified
    name: NotRequired[str | None]  # Full name
    given_name: NotRequired[str | None]  # First name
    family_name: NotRequired[str | None]  # Last name
    picture: NotRequired[str | None]  # Profile picture URL
    locale: NotRequired[str | None]  # User's locale


class GoogleOAuth2Config(OAuth2Config):
    """Google OAuth2 provider configuration."""

    name: str = "google"
    authorize_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: str = "https://oauth2.googleapis.com/token"
    userinfo_url: str = "https://www.googleapis.com/oauth2/v3/userinfo"
    scope: list[str] = [
        "openid",
        "email",
        "profile",
    ]


class GoogleOAuth2Provider(OAuth2Provider):
    """Google OAuth2 provider implementation."""

    async def get_user_info(self, token: dict[str, Any]) -> UserInfo:
        """Get user info from Google.

        Args:
            token: Access token response

        Returns:
            UserInfo: User info from Google

        Raises:
            HTTPException: If user info retrieval fails
        """
        try:
            resp = await self.client.get(
                self.config.userinfo_url,
                token=token,
            )
            resp.raise_for_status()
            user_info = resp.json()

            # Validate required fields
            if not isinstance(user_info, dict):
                raise ValueError("Invalid user info format")

            try:
                validated_info = GoogleUserInfo(
                    sub=user_info["sub"],
                    email=user_info["email"],
                    email_verified=user_info.get("email_verified", False),
                    name=user_info.get("name"),
                    given_name=user_info.get("given_name"),
                    family_name=user_info.get("family_name"),
                    picture=user_info.get("picture"),
                    locale=user_info.get("locale"),
                )
            except KeyError as e:
                raise ValueError(f"Missing required field: {e}")

            return UserInfo(
                provider="google",
                sub=validated_info["sub"],
                email=validated_info["email"],
                email_verified=validated_info["email_verified"],
                name=validated_info.get("name"),
                family_name=validated_info.get("family_name"),
                picture=validated_info.get("picture"),
                locale=validated_info.get("locale"),
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to get user info from Google: {str(e)}",
            ) from e
