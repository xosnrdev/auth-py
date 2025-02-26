"""SQLAlchemy audit log model for security tracking."""

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

MAX_ACTION_LENGTH: Final[int] = 50
MAX_IP_LENGTH: Final[int] = 45
PG_TIMESTAMP_FUNCTION: Final[str] = "CURRENT_TIMESTAMP"


class AuditLog(Base):
    """Security audit log with user tracking."""

    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text(PG_TIMESTAMP_FUNCTION),
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    action: Mapped[str] = mapped_column(
        String(MAX_ACTION_LENGTH),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(MAX_IP_LENGTH),
        nullable=False,
    )
    user_agent: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    details: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    user = relationship(
        "User",
        lazy="joined",
        innerjoin=True,
    )

    def __repr__(self) -> str:
        """Get string representation."""
        return f"<AuditLog {self.action} by {self.user_id.hex}>"
