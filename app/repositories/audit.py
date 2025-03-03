"""Audit log repository implementation."""

from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.repositories.base import BaseRepository

MAX_LOGS_PER_PAGE: Final[int] = 100
DEFAULT_LOGS_PER_PAGE: Final[int] = 20
MAX_DAYS_RANGE: Final[int] = 90


class AuditLogRepository(BaseRepository[AuditLog]):
    """Audit log repository with specialized audit operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize audit log repository.

        Args:
            session: SQLAlchemy async session
        """
        super().__init__(session, AuditLog)

    async def get_by_user(
        self,
        user_id: UUID,
        *,
        offset: int = 0,
        limit: int = DEFAULT_LOGS_PER_PAGE,
    ) -> list[AuditLog]:
        """Get audit logs for specific user.

        Args:
            user_id: User's UUID
            offset: Number of logs to skip
            limit: Maximum number of logs to return

        Returns:
            List of audit logs
        """
        assert user_id is not None, "User ID cannot be None"
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_LOGS_PER_PAGE, (
            f"Limit must be between 1 and {MAX_LOGS_PER_PAGE}"
        )

        query = (
            select(AuditLog)
            .where(AuditLog.user_id == user_id)
            .order_by(AuditLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def get_by_action(
        self,
        action: str,
        *,
        offset: int = 0,
        limit: int = DEFAULT_LOGS_PER_PAGE,
    ) -> list[AuditLog]:
        """Get audit logs for specific action.

        Args:
            action: Action type
            offset: Number of logs to skip
            limit: Maximum number of logs to return

        Returns:
            List of audit logs
        """
        assert action, "Action cannot be empty"
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_LOGS_PER_PAGE, (
            f"Limit must be between 1 and {MAX_LOGS_PER_PAGE}"
        )

        query = (
            select(AuditLog)
            .where(AuditLog.action == action)
            .order_by(AuditLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def get_by_ip_address(
        self,
        ip_address: str,
        *,
        action: str | None = None,
        since: datetime | None = None,
        offset: int = 0,
        limit: int = DEFAULT_LOGS_PER_PAGE,
    ) -> list[AuditLog]:
        """Get audit logs from specific IP address.

        Args:
            ip_address: IP address
            action: Optional action type to filter by
            since: Optional datetime to filter logs since
            offset: Number of logs to skip
            limit: Maximum number of logs to return

        Returns:
            List of audit logs
        """
        assert ip_address, "IP address cannot be empty"
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_LOGS_PER_PAGE, (
            f"Limit must be between 1 and {MAX_LOGS_PER_PAGE}"
        )

        query = select(AuditLog).where(AuditLog.ip_address == ip_address)
        if action:
            query = query.where(AuditLog.action == action)
        if since:
            assert since.tzinfo is not None, "Datetime must be timezone-aware"
            query = query.where(AuditLog.timestamp >= since)
        query = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)

        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def get_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime | None = None,
        *,
        offset: int = 0,
        limit: int = DEFAULT_LOGS_PER_PAGE,
    ) -> list[AuditLog]:
        """Get audit logs within date range.

        Args:
            start_date: Start date (inclusive)
            end_date: End date (inclusive), defaults to current time
            offset: Number of logs to skip
            limit: Maximum number of logs to return

        Returns:
            List of audit logs
        """
        assert start_date is not None, "Start date cannot be None"
        assert start_date.tzinfo is not None, "Start date must be timezone-aware"

        # Set end_date to current time if not provided
        if end_date is None:
            end_date = datetime.now(UTC)
        else:
            assert end_date.tzinfo is not None, "End date must be timezone-aware"

        # Validate date range
        date_range = end_date - start_date
        assert date_range.days <= MAX_DAYS_RANGE, (
            f"Date range cannot exceed {MAX_DAYS_RANGE} days"
        )
        assert date_range.days >= 0, "End date must be after start date"

        # Validate pagination
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_LOGS_PER_PAGE, (
            f"Limit must be between 1 and {MAX_LOGS_PER_PAGE}"
        )

        query = (
            select(AuditLog)
            .where(
                AuditLog.timestamp >= start_date,
                AuditLog.timestamp <= end_date,
            )
            .order_by(AuditLog.timestamp.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all())
