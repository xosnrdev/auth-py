"""Base schemas for all Pydantic models."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class BaseSchema(BaseModel):
    """Base schema with common functionality."""

    model_config = ConfigDict(
        from_attributes=True,  # Allow ORM model conversion
        json_schema_extra={"example": {}},  # Base for examples
        populate_by_name=True,  # Allow population by alias
    )

    id: UUID
    created_at: datetime
    updated_at: datetime
