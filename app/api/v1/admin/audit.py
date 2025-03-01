"""Audit log endpoints for tracking user activity."""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, HTTPException, status

from app.core.auth import requires_admin
from app.core.dependencies import AuditRepo, CurrentUser
from app.core.errors import AuditError
from app.models import AuditLog
from app.schemas import AuditLogResponse
from app.services import AuditService

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

    Raises:
        HTTPException: If log retrieval fails
    """
    try:
        audit_service = AuditService(audit_repo)
        return await audit_service.get_logs(
            user_id=user_id,
            action=action,
            start_date=start_date,
            end_date=end_date,
            skip=skip,
            limit=limit,
        )
    except AuditError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
        audit_service = AuditService(audit_repo)
        return await audit_service.get_log(log_id)
    except AuditError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
