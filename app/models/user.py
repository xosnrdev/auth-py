"""SQLAlchemy User model with role-based access control.

Example:
```python
# Create new user
user = User(
    email="user@example.com",
    phone="+1234567890",          # Optional, E.164 format
    password_hash="bcrypt$...",   # From password hasher
    roles=["user", "admin"],      # Default: ["user"]
    is_verified=False,            # Email verification
    is_active=True               # Account status
)

# Check permissions
if user.has_role("admin"):
    # Admin operations
    pass

if user.has_any_role(["admin", "moderator"]):
    # Staff operations
    pass

if user.has_all_roles(["user", "premium"]):
    # Premium user operations
    pass
```

Critical Notes:
- All timestamps use UTC
- Email must be unique
- Phone must be E.164 format
- Password uses bcrypt hash
- Default role is "user"
- Verification codes expire
- Reset tokens expire
"""

from datetime import datetime
from typing import Final

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base

# Constants
MAX_EMAIL_LENGTH: Final[int] = 255
MAX_PHONE_LENGTH: Final[int] = 20
MAX_VERIFICATION_CODE_LENGTH: Final[int] = 32
MAX_RESET_TOKEN_LENGTH: Final[int] = 64
DEFAULT_ROLE: Final[str] = "user"


class User(Base):
    """User model with role-based access control."""

    __tablename__ = "users"

    # Authentication fields
    email: Mapped[str] = mapped_column(
        String(MAX_EMAIL_LENGTH),
        unique=True,
        nullable=False,
        index=True,
    )
    phone: Mapped[str | None] = mapped_column(
        String(MAX_PHONE_LENGTH),
        unique=True,
        nullable=True,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    social_id: Mapped[dict[str, str]] = mapped_column(
        JSONB,
        nullable=False,
        server_default="{}",
    )

    # Role-based access control
    roles: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=f'["{DEFAULT_ROLE}"]',
    )

    # Status fields
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="true",
    )

    # Email verification
    verification_code: Mapped[str | None] = mapped_column(
        String(MAX_VERIFICATION_CODE_LENGTH),
        nullable=True,
        index=True,
    )
    verification_code_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Password reset
    reset_token: Mapped[str | None] = mapped_column(
        String(MAX_RESET_TOKEN_LENGTH),
        nullable=True,
        index=True,
    )
    reset_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role."""
        assert role, "Role cannot be empty"
        return role in self.roles

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the roles."""
        assert roles, "Roles list cannot be empty"
        return bool(set(self.roles) & set(roles))

    def has_all_roles(self, roles: list[str]) -> bool:
        """Check if user has all roles."""
        assert roles, "Roles list cannot be empty"
        return set(roles).issubset(set(self.roles))

    def __repr__(self) -> str:
        """Get string representation."""
        return f"<User {self.email}>"
