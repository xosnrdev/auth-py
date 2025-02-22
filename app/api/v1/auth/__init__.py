"""Authentication package for all auth-related routes."""

from app.api.v1.auth.auth import router as auth_router
from app.api.v1.auth.dependencies import CurrentUser
from app.api.v1.auth.social import ProviderType
from app.api.v1.auth.social import router as social_router

__all__ = [
    "auth_router",
    "social_router",
    "CurrentUser",
    "ProviderType",
]
