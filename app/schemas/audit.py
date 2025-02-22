"""Audit log schemas for tracking user actions."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.base import BaseSchema


class AuditLogBase(BaseModel):
    """Base schema for audit log data."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "action": "login",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...",
                "details": "Login successful",
            }
        },
    )

    action: str = Field(
        description="Action performed",
        examples=["login", "logout", "password_reset"],
        max_length=50,
    )
    ip_address: str = Field(
        description="IP address of the client",
        examples=["192.168.1.1", "2001:db8::1"],
        max_length=45,  # IPv6 max length
    )
    user_agent: str = Field(
        description="User agent string of the client",
    )
    details: str | None = Field(
        default=None,
        description="Additional details about the action",
    )


class AuditLogCreate(AuditLogBase):
    """Schema for creating an audit log entry."""

    user_id: UUID = Field(
        description="ID of the user who performed the action",
    )


class AuditLogResponse(AuditLogBase, BaseSchema):
    """Schema for audit log responses."""

    timestamp: datetime = Field(
        description="When the action was performed",
    )
    user_id: UUID = Field(
        description="ID of the user who performed the action",
    )
