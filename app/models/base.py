"""SQLAlchemy base model with UUID and timestamps."""

from datetime import UTC, datetime
from typing import TypedDict
from uuid import UUID, uuid4

from sqlalchemy import DateTime, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class BaseModelDict(TypedDict):
    """Base model serialized form."""

    id: str
    created_at: str
    updated_at: str


class Base(DeclarativeBase):
    """Base model with UUID and timestamps."""

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=uuid4,
        server_default=func.gen_random_uuid(),
        comment="Primary key ID",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        comment="Created at timestamp",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
        comment="Updated at timestamp",
    )

    def dict(self) -> BaseModelDict:
        """Convert model to dict with hex UUIDs."""
        return BaseModelDict(
            id=self.id.hex,
            created_at=self.created_at.astimezone(UTC).isoformat(),
            updated_at=self.updated_at.astimezone(UTC).isoformat(),
        )
