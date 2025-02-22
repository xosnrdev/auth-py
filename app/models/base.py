from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import DateTime, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all database models."""

    # Common fields for all models
    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
        server_default=text("gen_random_uuid()"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
    )

    def dict(self) -> dict[str, Any]:
        """Convert model to dictionary.

        Returns:
            dict[str, Any]: Dictionary representation of model with UUIDs as hex strings
        """
        result = {}
        for c in self.__table__.columns:
            value = getattr(self, c.name)
            if isinstance(value, UUID):
                result[c.name] = value.hex
            else:
                result[c.name] = value
        return result
