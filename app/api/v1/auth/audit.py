"""Audit log endpoints for tracking user activity."""

from datetime import datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.v1.auth.dependencies import CurrentUser, DBSession
from app.core.auth import requires_admin
from app.models import AuditLog
from app.schemas import AuditLogResponse
from app.utils.request import get_client_ip

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs", response_model=list[AuditLogResponse])
@requires_admin
async def list_audit_logs(
    db: DBSession,
    _: CurrentUser,  # Required by @requires_admin
    user_id: UUID | None = None,
    action: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    skip: int = 0,
    limit: int = 100,
) -> list[AuditLog]:
    """List audit logs with optional filters (admin only)."""
    # Build query
    stmt = select(AuditLog)

    # Apply filters
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if start_date:
        stmt = stmt.where(AuditLog.created_at >= start_date)
    if end_date:
        stmt = stmt.where(AuditLog.created_at <= end_date)

    # Add pagination
    stmt = stmt.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)

    # Execute query
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/logs/{log_id}", response_model=AuditLogResponse)
@requires_admin
async def get_audit_log(
    log_id: UUID,
    db: DBSession,
    _: CurrentUser,  # Required by @requires_admin
) -> AuditLog:
    """Get audit log by ID (admin only)."""
    stmt = select(AuditLog).where(AuditLog.id == log_id)
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )
    return log


@router.get("/me/logs", response_model=list[AuditLogResponse])
async def list_my_audit_logs(
    request: Request,
    db: DBSession,
    current_user: CurrentUser,
    action: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    skip: int = 0,
    limit: int = 100,
) -> list[AuditLog]:
    """List current user's audit logs with optional filters."""
    # Build query
    stmt = select(AuditLog).where(AuditLog.user_id == current_user.id)

    # Apply filters
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if start_date:
        stmt = stmt.where(AuditLog.created_at >= start_date)
    if end_date:
        stmt = stmt.where(AuditLog.created_at <= end_date)

    # Add pagination
    stmt = stmt.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit)

    # Log access
    audit_log = AuditLog(
        user_id=current_user.id,
        action="view_audit_logs",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Viewed personal audit logs",
    )
    db.add(audit_log)

    # Execute query
    result = await db.execute(stmt)
    logs = list(result.scalars().all())

    await db.commit()
    return logs


@router.get("/me/logs/recent", response_model=list[AuditLogResponse])
async def list_recent_activity(
    request: Request,
    db: DBSession,
    current_user: CurrentUser,
    days: int = 7,
    limit: int = 10,
) -> list[AuditLog]:
    """List current user's recent activity."""
    # Build query
    stmt = (
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .where(AuditLog.created_at >= datetime.utcnow() - timedelta(days=days))
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )

    # Log access
    audit_log = AuditLog(
        user_id=current_user.id,
        action="view_recent_activity",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Viewed recent activity",
    )
    db.add(audit_log)

    # Execute query
    result = await db.execute(stmt)
    logs = list(result.scalars().all())

    await db.commit()
    return logs
