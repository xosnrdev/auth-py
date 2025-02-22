from typing import Any

from sqlalchemy import Boolean, String, Text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class User(Base):
    """User model for authentication and authorization."""

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

    # Authorization fields
    roles: Mapped[list[str]] = mapped_column(
        ARRAY(String),
        nullable=False,
        server_default="{user}",
    )

    def __repr__(self) -> str:
        """String representation of User model."""
        return f"<User {self.email}>"
