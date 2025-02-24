"""Authentication router for login, logout, and token management."""

from fastapi import APIRouter

from app.api.v1.auth.social import router as social_router
from app.api.v1.auth.token import router as token_router

router = APIRouter(tags=["auth"])

router.include_router(token_router)
router.include_router(social_router)
