"""SQLAlchemy audit log model for security tracking.

Example:
```python
# Create audit log entry
log = AuditLog(
    user_id="123e4567-...",        # References users.id
    action="login",                # Limited to 50 chars
    ip_address="192.168.1.1",     # IPv4/IPv6
    user_agent="Mozilla/5.0...",   # Browser info
    details="2FA successful"       # Optional context
)
# timestamp: auto-set to current UTC
# created_at/updated_at: from Base

# Access related user (auto-joined)
assert log.user.email == "user@example.com"
```

Critical Notes:
- All timestamps in UTC
- User ID must exist (CASCADE delete)
- Actions indexed for fast search
- IP addresses: IPv4/IPv6 format
- User agents stored as text
- Auto-joins user relation
"""

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

# Constants
MAX_ACTION_LENGTH: Final[int] = 50
MAX_IP_LENGTH: Final[int] = 45  # IPv6 max length
PG_TIMESTAMP_FUNCTION: Final[str] = "CURRENT_TIMESTAMP"


class AuditLog(Base):
    """Security audit log with user tracking."""

    __tablename__ = "audit_logs"

    # Event timestamp
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text(PG_TIMESTAMP_FUNCTION),
    )

    # User reference
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Event details
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

    # Auto-joined user
    user = relationship(
        "User",
        lazy="joined",
        innerjoin=True,
    )

    def __repr__(self) -> str:
        """Get string representation."""
        return f"<AuditLog {self.action} by {self.user_id.hex}>"
