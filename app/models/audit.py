"""SQLAlchemy audit log model for security tracking."""

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, BaseModelDict
from .user import User

MAX_ACTION_LENGTH: Final[int] = 50
MAX_IP_LENGTH: Final[int] = 45


class AuditLogModelDict(BaseModelDict):
    """Audit log model serialized form."""

    timestamp: str
    user_id: str | None
    action: str
    ip_address: str
    user_agent: str
    details: str | None


class AuditLog(Base):
    """Security audit log with user tracking."""

    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.current_timestamp(),
        index=True,
        comment="Event timestamp in UTC",
    )

    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
        comment="User who performed the action (NULL for non-existent users)",
    )

    action: Mapped[str] = mapped_column(
        String(MAX_ACTION_LENGTH),
        nullable=False,
        index=True,
        comment="Action performed (e.g. login, update_profile)",
    )
    ip_address: Mapped[str] = mapped_column(
        String(MAX_IP_LENGTH),
        nullable=False,
        index=True,
        comment="Client IP address",
    )
    user_agent: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        comment="Client user agent string",
    )
    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Additional event details in JSON format",
    )

    user: Mapped["User | None"] = relationship(
        "User",
        lazy="joined",
        innerjoin=False,
        back_populates="audit_logs",
    )

    __table_args__ = (
        Index(
            "ix_audit_logs_user_timeline",
            "user_id",
            "timestamp",
            "action",
        ),
        Index(
            "ix_audit_logs_security",
            "ip_address",
            "action",
            "timestamp",
        ),
        Index(
            "ix_audit_logs_failed_logins",
            "user_id",
            "action",
            "timestamp",
            postgresql_where=action == "login_failed",
        ),
    )

    def __repr__(self) -> str:
        """Get string representation."""
        return f"<AuditLog {self.action} by {self.user_id.hex if self.user_id else 'unknown'}>"

    def dict(self) -> AuditLogModelDict:
        """Convert model to dict with serialized values.

        Returns:
            Dictionary representation of the audit log
        """
        base_dict = super().dict()
        return AuditLogModelDict(
            **base_dict,
            timestamp=self.timestamp.isoformat(),
            user_id=self.user_id.hex if self.user_id else None,
            action=self.action,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            details=self.details,
        )
