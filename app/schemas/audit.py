"""Security audit log schemas for tracking user actions.

Example:
```python
# Create audit log entry
log = AuditLogCreate(
    action="login",                # Limited to 50 chars
    ip_address="192.168.1.1",     # IPv4 or IPv6
    user_agent="Mozilla/5.0...",   # Browser info
    details="2FA successful",      # Optional context
    user_id="123e4567-..."        # User who acted
)

# Response includes timestamps
response = AuditLogResponse(
    **log.model_dump(),
    id="987fcdeb-...",
    created_at="2025-02-23T10:20:30Z",
    updated_at="2025-02-23T10:20:30Z",
    timestamp="2025-02-23T10:20:30Z"
)
```

Critical Notes:
- All timestamps in UTC
- IP addresses: IPv4 or IPv6 format
- Actions limited to 50 chars
- User agents truncated to 512 chars
- Details field optional, max 1024 chars
"""

import re
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.base import BaseSchema

# Constants
MAX_ACTION_LENGTH: Final[int] = 50
MAX_IP_LENGTH: Final[int] = 45
MAX_USER_AGENT_LENGTH: Final[int] = 512
MAX_DETAILS_LENGTH: Final[int] = 1024

# Patterns
IPV4_PATTERN: Final[str] = r"^(?:\d{1,3}\.){3}\d{1,3}$"
IPV6_PATTERN: Final[str] = r"^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$"


class AuditLogBase(BaseModel):
    """Base audit log fields."""

    model_config = ConfigDict(from_attributes=True)

    action: str = Field(
        max_length=MAX_ACTION_LENGTH,
        examples=["login", "password_reset"],
    )
    ip_address: str = Field(
        max_length=MAX_IP_LENGTH,
        examples=["192.168.1.1", "2001:db8::1"],
    )
    user_agent: str = Field(
        max_length=MAX_USER_AGENT_LENGTH,
        examples=["Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)..."],
    )
    details: str | None = Field(
        default=None,
        max_length=MAX_DETAILS_LENGTH,
        examples=["2FA verification successful"],
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


class AuditLogCreate(AuditLogBase):
    """New audit log entry."""

    user_id: UUID = Field(
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )


class AuditLogResponse(AuditLogBase, BaseSchema):
    """Audit log entry with timestamps."""

    timestamp: datetime = Field(
        examples=["2025-02-23T10:20:30.123Z"],
    )
    user_id: UUID = Field(
        examples=["123e4567-e89b-12d3-a456-426614174000"],
    )

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        """Ensure timestamp is UTC."""
        assert v.tzinfo is not None, "Timestamp must be timezone-aware"
        return v.astimezone(UTC)
