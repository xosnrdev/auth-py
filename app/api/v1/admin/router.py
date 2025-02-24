"""Administrative router for user and system management."""

from fastapi import APIRouter

from app.api.v1.admin.admin import router as admin_router
from app.api.v1.admin.audit import router as audit_router

router = APIRouter(tags=["admin"])

router.include_router(admin_router)
router.include_router(audit_router)
