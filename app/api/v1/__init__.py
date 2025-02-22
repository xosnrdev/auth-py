"""API v1 package."""

from fastapi import APIRouter

from app.api.v1.auth.router import router as auth_router

# Create v1 router
router = APIRouter(prefix="/v1")

# Include all routers
router.include_router(auth_router)
