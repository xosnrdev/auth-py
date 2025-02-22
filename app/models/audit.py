from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class AuditLog(Base):
    """Audit log model for tracking user actions."""

    __tablename__ = "audit_logs"

    # Audit fields
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )
    ip_address: Mapped[str] = mapped_column(
        String(45),  # IPv6 max length
        nullable=False,
    )
    user_agent: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    details: Mapped[str] = mapped_column(
        Text,
        nullable=True,
    )

    # Relationships
    user = relationship(
        "User",
        lazy="joined",
        innerjoin=True,
    )

    def __repr__(self) -> str:
        """String representation of AuditLog model."""
        return f"<AuditLog {self.action} by {self.user_id.hex}>"
