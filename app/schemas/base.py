"""Base schema with common fields for all models."""

from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

EXAMPLE_UUID: Final[str] = "123e4567-e89b-12d3-a456-426614174000"
EXAMPLE_TIMESTAMP: Final[str] = "2025-02-23T10:20:30.123Z"


class BaseSchema(BaseModel):
    """Common fields for all models."""

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
    )

    id: UUID = Field(
        examples=[EXAMPLE_UUID],
    )
    created_at: datetime = Field(
        examples=[EXAMPLE_TIMESTAMP],
    )
    updated_at: datetime = Field(
        examples=[EXAMPLE_TIMESTAMP],
    )

    @field_validator("created_at", "updated_at")
    @classmethod
    def validate_timestamps(cls, v: datetime) -> datetime:
        """Ensure timestamps are UTC."""
        assert v.tzinfo is not None, "Timestamp must be timezone-aware"
        return v.astimezone(UTC)
