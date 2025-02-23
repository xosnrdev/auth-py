"""Audit log endpoints for tracking user activity.

This module implements secure audit logging functionality including:
- Administrative audit log access
- User activity tracking
- Filtered log retrieval
- Recent activity monitoring
Following security best practices and privacy considerations.
"""

from datetime import UTC, datetime, timedelta
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
    """List audit logs with comprehensive filtering and pagination.

    Implements secure audit log retrieval:
    1. Role-based access control (admin only)
    2. Multiple filter criteria
    3. Date range filtering
    4. Pagination for large datasets
    5. Ordered by timestamp

    Args:
        db: Database session
        _: Current admin user (required by @requires_admin decorator)
        user_id: Optional filter by specific user
        action: Optional filter by action type
        start_date: Optional filter by start date
        end_date: Optional filter by end date
        skip: Number of records to skip (pagination)
        limit: Maximum number of records to return

    Returns:
        list[AuditLog]: List of audit logs matching criteria

    Security:
        - Requires admin role
        - Implements pagination
        - Supports data filtering
        - Rate limited by default middleware
    """
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
    """Get specific audit log entry by ID.

    Implements secure audit log retrieval:
    1. Role-based access control (admin only)
    2. UUID validation
    3. Not found handling
    4. Single record access

    Args:
        log_id: UUID of the audit log to retrieve
        db: Database session
        _: Current admin user (required by @requires_admin decorator)

    Returns:
        AuditLog: Specific audit log entry

    Raises:
        HTTPException: If log entry not found (404)

    Security:
        - Requires admin role
        - Validates UUID format
        - Rate limited by default middleware
    """
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
    """List current user's audit logs with filtering options.

    Implements secure personal audit log access:
    1. User-specific data access
    2. Multiple filter criteria
    3. Date range filtering
    4. Pagination for large datasets
    5. Access logging
    6. Ordered by timestamp

    Args:
        request: FastAPI request object
        db: Database session
        current_user: Current authenticated user
        action: Optional filter by action type
        start_date: Optional filter by start date
        end_date: Optional filter by end date
        skip: Number of records to skip (pagination)
        limit: Maximum number of records to return

    Returns:
        list[AuditLog]: List of user's audit logs matching criteria

    Security:
        - User-specific data isolation
        - Implements pagination
        - Logs access attempts
        - Rate limited by default middleware
    """
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
    """List current user's recent activity with time window.

    Implements secure recent activity tracking:
    1. User-specific data access
    2. Time window filtering
    3. Limited result set
    4. Access logging
    5. Ordered by timestamp

    Args:
        request: FastAPI request object
        db: Database session
        current_user: Current authenticated user
        days: Number of days to look back
        limit: Maximum number of records to return

    Returns:
        list[AuditLog]: List of recent user activity

    Security:
        - User-specific data isolation
        - Time-boxed queries
        - Logs access attempts
        - Rate limited by default middleware
    """
    # Build query
    stmt = (
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .where(AuditLog.created_at >= datetime.now(UTC) - timedelta(days=days))
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
