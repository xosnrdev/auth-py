"""Security audit log schemas for tracking user actions."""

import re
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.base import BaseSchema

MAX_ACTION_LENGTH: Final[int] = 50
MAX_IP_LENGTH: Final[int] = 45
MAX_USER_AGENT_LENGTH: Final[int] = 512
MAX_DETAILS_LENGTH: Final[int] = 1024

IPV4_PATTERN: Final[str] = r"^(?:\d{1,3}\.){3}\d{1,3}$"
IPV6_PATTERN: Final[str] = r"^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$"


class AuditLogBase(BaseModel):
    """Base audit log data validation."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "action": "login",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
                "details": "User logged in successfully",
            }
        },
        populate_by_name=True,
    )

    action: str = Field(
        max_length=MAX_ACTION_LENGTH,
        description="Action performed (e.g. login, update_profile)",
        examples=["login", "update_profile", "password_reset"],
    )
    ip_address: str = Field(
        description="Client IP address",
        examples=["192.168.1.1", "2001:db8::1"],
    )
    user_agent: str = Field(
        description="Client user agent string",
        examples=["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
    )
    details: str | None = Field(
        default=None,
        description="Additional event details in JSON format",
        examples=["User logged in successfully", "Password reset requested"],
    )


class AuditLogCreate(AuditLogBase):
    """Audit log creation data."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "login",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
                "details": "User logged in successfully",
            }
        },
    )

    user_id: UUID | None = Field(
        default=None,
        description="ID of the user who performed the action",
    )

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IPv4 or IPv6 address."""
        v = v.upper()
        is_ipv4 = bool(re.match(IPV4_PATTERN, v))
        is_ipv6 = bool(re.match(IPV6_PATTERN, v))
        assert is_ipv4 or is_ipv6, "Invalid IP address format"
        return v


class AuditLogResponse(AuditLogBase, BaseSchema):
    """Audit log data for responses."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "timestamp": "2024-01-01T00:00:00Z",
                "user_id": "123e4567-e89b-12d3-a456-426614174000",
                "action": "login",
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0",
                "details": "User logged in successfully",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        },
    )

    timestamp: datetime = Field(
        description="Event timestamp in UTC",
    )
    user_id: UUID | None = Field(
        default=None,
        description="ID of the user who performed the action",
    )

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        """Ensure timestamp is UTC."""
        assert v.tzinfo is not None, "Timestamp must be timezone-aware"
        return v.astimezone(UTC)
