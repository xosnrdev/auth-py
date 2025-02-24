"""API v1 router configuration."""

from fastapi import APIRouter

from app.api.v1.admin import router as admin_router
from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router

# Create v1 router
router = APIRouter(prefix="/v1")

# Include all routers
router.include_router(auth_router, prefix="/auth")
router.include_router(users_router, prefix="/users")
router.include_router(admin_router, prefix="/admin")
