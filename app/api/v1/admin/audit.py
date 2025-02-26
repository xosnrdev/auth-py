"""Audit log endpoints for tracking user activity."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.api.v1.dependencies import CurrentUser, DBSession
from app.core.auth import requires_admin
from app.models import AuditLog
from app.schemas import AuditLogResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs", response_model=list[AuditLogResponse])
@requires_admin
async def list_audit_logs(
    db: DBSession,
    _: CurrentUser,
    user_id: UUID | None = None,
    action: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    skip: int = 0,
    limit: int = 100,
) -> list[AuditLog]:
    """List audit logs with comprehensive filtering and pagination."""
    stmt = select(AuditLog)

    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if start_date:
        stmt = stmt.where(AuditLog.created_at >= start_date)
    if end_date:
        stmt = stmt.where(AuditLog.created_at <= end_date)

    stmt = stmt.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/logs/{log_id}", response_model=AuditLogResponse)
@requires_admin
async def get_audit_log(
    log_id: UUID,
    db: DBSession,
    _: CurrentUser,
) -> AuditLog:
    """Get specific audit log entry by ID."""
    stmt = select(AuditLog).where(AuditLog.id == log_id)
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )
    return log
