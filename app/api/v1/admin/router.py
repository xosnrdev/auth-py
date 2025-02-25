"""Administrative router for user and system management."""

from fastapi import APIRouter

from app.api.v1.admin.audit import router as audit_router
from app.api.v1.admin.users import router as users_router

router = APIRouter(tags=["admin"])

router.include_router(users_router)
router.include_router(audit_router)
