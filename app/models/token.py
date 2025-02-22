"""Token model for JWT token management."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class Token(Base):
    """Token model for refresh token management.

    Note: Access tokens are not stored as they are stateless JWTs that can be
    validated using the public key. Only refresh tokens are stored for revocation
    and rotation purposes.
    """

    __tablename__ = "tokens"

    # Token fields
    jti: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    refresh_token: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        unique=True,
        index=True,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
    )
    token_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        server_default="bearer",
    )

    # Relationships
    user = relationship(
        "User",
        lazy="joined",
        innerjoin=True,
    )

    def __repr__(self) -> str:
        """String representation of Token model."""
        return f"<Token {self.jti}>"
