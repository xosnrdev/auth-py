"""Audit log service for managing system audit trails."""

import logging
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from app.core.errors import AuditError, NotFoundError
from app.models import AuditLog
from app.repositories import AuditLogRepository
from app.schemas.audit import AuditLogCreate

logger = logging.getLogger(__name__)

MAX_LOGS_PER_PAGE: Final[int] = 100
DEFAULT_LOGS_PER_PAGE: Final[int] = 20
MAX_DAYS_RANGE: Final[int] = 90


class AuditService:
    """Service for managing system audit logs.

    This service handles:
    - Audit log retrieval with filtering
    - Audit log access control
    - Audit trail management
    """

    def __init__(self, audit_repo: AuditLogRepository) -> None:
        """Initialize audit service.

        Args:
            audit_repo: Audit log repository
        """
        self._audit_repo = audit_repo

    async def get_logs(
        self,
        *,
        user_id: UUID | None = None,
        action: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        skip: int = 0,
        limit: int = DEFAULT_LOGS_PER_PAGE,
    ) -> list[AuditLog]:
        """Get audit logs with filtering and pagination.

        Args:
            user_id: Filter by user ID
            action: Filter by action type
            start_date: Filter by start date
            end_date: Filter by end date
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of audit logs

        Raises:
            AuditError: If log retrieval fails
        """
        try:
            # Validate pagination
            if skip < 0:
                raise ValueError("Skip must be non-negative")
            if not 0 < limit <= MAX_LOGS_PER_PAGE:
                raise ValueError(f"Limit must be between 1 and {MAX_LOGS_PER_PAGE}")

            # If no filters are applied, use get_all
            if not any([user_id, action, start_date, end_date]):
                return await self._audit_repo.get_all(offset=skip, limit=limit)

            # Apply filters in priority order
            if user_id:
                return await self._audit_repo.get_by_user(
                    user_id, offset=skip, limit=limit
                )
            elif action:
                return await self._audit_repo.get_by_action(
                    action, offset=skip, limit=limit
                )
            else:
                return await self._audit_repo.get_by_date_range(
                    start_date=start_date or datetime.now(UTC),
                    end_date=end_date,
                    offset=skip,
                    limit=limit,
                )

        except ValueError as e:
            raise AuditError(str(e))
        except Exception as e:
            logger.error("Failed to retrieve audit logs: %s", str(e))
            raise AuditError("Failed to retrieve audit logs")

    async def get_log(self, log_id: UUID) -> AuditLog:
        """Get specific audit log by ID.

        Args:
            log_id: Audit log ID

        Returns:
            Audit log entry

        Raises:
            AuditError: If log retrieval fails
        """
        try:
            return await self._audit_repo.get_by_id(log_id)
        except NotFoundError:
            raise AuditError("Audit log not found")
        except Exception as e:
            logger.error("Failed to retrieve audit log: %s", str(e))
            raise AuditError("Failed to retrieve audit log")

    async def create_log(self, log_data: AuditLogCreate) -> AuditLog:
        """Create a new audit log entry.

        Args:
            log_data: Audit log data

        Returns:
            Created audit log

        Raises:
            AuditError: If log creation fails
        """
        try:
            # Convert schema to dict and add timestamp
            create_data = log_data.model_dump()
            create_data["timestamp"] = datetime.now(UTC)

            # Create audit log
            return await self._audit_repo.create(create_data)
        except Exception as e:
            raise AuditError(f"Failed to create audit log: {str(e)}")
