from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class User(Base):
    """User model for authentication."""

    __tablename__ = "users"

    # Authentication fields
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
    )
    phone: Mapped[str | None] = mapped_column(
        String(20),
        unique=True,
        nullable=True,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    social_id: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default="{}",
    )

    # Role-based access control
    roles: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        server_default='["user"]',  # Default role for all users
        comment="User roles for RBAC (e.g., user, admin)",
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
        String(32),  # Store verification code
        nullable=True,
        index=True,
    )
    verification_code_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # Password reset
    reset_token: Mapped[str | None] = mapped_column(
        String(64),  # Store reset token
        nullable=True,
        index=True,
    )
    reset_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def has_role(self, role: str) -> bool:
        """Check if user has a specific role.

        Args:
            role: Role to check

        Returns:
            bool: True if user has the role
        """
        return role in self.roles

    def has_any_role(self, roles: list[str]) -> bool:
        """Check if user has any of the specified roles.

        Args:
            roles: List of roles to check

        Returns:
            bool: True if user has any of the roles
        """
        return bool(set(self.roles) & set(roles))

    def has_all_roles(self, roles: list[str]) -> bool:
        """Check if user has all specified roles.

        Args:
            roles: List of roles to check

        Returns:
            bool: True if user has all roles
        """
        return set(roles).issubset(set(self.roles))

    def __repr__(self) -> str:
        """String representation of User model."""
        return f"<User {self.email}>"
