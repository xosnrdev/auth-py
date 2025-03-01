"""Audit log endpoints for tracking user activity."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.api.v1.dependencies import AuditRepo, CurrentUser
from app.core.auth import requires_admin
from app.core.errors import NotFoundError
from app.models import AuditLog
from app.schemas import AuditLogResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("/logs", response_model=list[AuditLogResponse])
@requires_admin
async def list_audit_logs(
    audit_repo: AuditRepo,
    _: CurrentUser,
    user_id: UUID | None = None,
    action: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    skip: int = 0,
    limit: int = 100,
) -> list[AuditLog]:
    """List audit logs with comprehensive filtering and pagination.

    Args:
        audit_repo: Audit log repository
        _: Current authenticated user (unused)
        user_id: Filter by user ID
        action: Filter by action type
        start_date: Filter by start date
        end_date: Filter by end date
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        List of audit logs
    """
    # If no filters are applied, use get_all
    if not any([user_id, action, start_date, end_date]):
        return await audit_repo.get_all(offset=skip, limit=limit)

    # Apply filters in priority order
    if user_id:
        return await audit_repo.get_by_user(user_id, offset=skip, limit=limit)
    elif action:
        return await audit_repo.get_by_action(action, offset=skip, limit=limit)
    else:
        return await audit_repo.get_by_date_range(
            start_date=start_date or datetime.now(UTC),
            end_date=end_date,
            offset=skip,
            limit=limit,
        )


@router.get("/logs/{log_id}", response_model=AuditLogResponse)
@requires_admin
async def get_audit_log(
    log_id: UUID,
    audit_repo: AuditRepo,
    _: CurrentUser,
) -> AuditLog:
    """Get specific audit log entry by ID.

    Args:
        log_id: Audit log ID to get
        audit_repo: Audit log repository
        _: Current authenticated user (unused)

    Returns:
        Audit log entry

    Raises:
        HTTPException: If log not found
    """
    try:
        return await audit_repo.get_by_id(log_id)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found",
        )
