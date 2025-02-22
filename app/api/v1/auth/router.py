"""Main router for authentication endpoints."""

from fastapi import APIRouter

from app.api.v1.auth import admin, audit, auth, social, users

router = APIRouter(prefix="/auth", tags=["auth"])

# Include sub-routers
router.include_router(auth.router)
router.include_router(users.router)
router.include_router(admin.router)
router.include_router(audit.router)
router.include_router(social.router)
