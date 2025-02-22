"""Authentication package for all auth-related routes."""

from app.api.v1.auth.router import router
from app.api.v1.auth.social import router as social_router

# Include social auth routes
router.include_router(social_router)

__all__ = ["router"]
