"""SQLAlchemy base model with UUID and timestamps."""

from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID, uuid4

from sqlalchemy import DateTime, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

UUID_LENGTH: Final[int] = 32
TIMESTAMP_FORMAT: Final[str] = 'YYYY-MM-DD"T"HH24:MI:SS.US"TZ"'
PG_UUID_FUNCTION: Final[str] = "gen_random_uuid()"
PG_TIMESTAMP_FUNCTION: Final[str] = "CURRENT_TIMESTAMP"


class Base(DeclarativeBase):
    """Base model with UUID and timestamps."""

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
        server_default=text(PG_UUID_FUNCTION),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text(PG_TIMESTAMP_FUNCTION),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text(PG_TIMESTAMP_FUNCTION),
        onupdate=text(PG_TIMESTAMP_FUNCTION),
    )

    def dict(self) -> dict[str, Any]:
        """Convert model to dict with hex UUIDs."""
        result: dict[str, Any] = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, UUID):
                assert len(value.hex) == UUID_LENGTH, "Invalid UUID length"
                result[column.name] = value.hex
            elif isinstance(value, datetime):
                assert value.tzinfo is not None, "Timestamp must be timezone-aware"
                result[column.name] = value.astimezone(UTC).isoformat()
            else:
                result[column.name] = value
        return result
