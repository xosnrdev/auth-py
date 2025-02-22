"""OAuth2 provider implementations."""

from app.core.oauth2.apple import AppleOAuth2Config, AppleOAuth2Provider
from app.core.oauth2.base import OAuth2Config, OAuth2Provider
from app.core.oauth2.google import GoogleOAuth2Config, GoogleOAuth2Provider

__all__ = [
    "OAuth2Config",
    "OAuth2Provider",
    "GoogleOAuth2Config",
    "GoogleOAuth2Provider",
    "AppleOAuth2Config",
    "AppleOAuth2Provider",
]
