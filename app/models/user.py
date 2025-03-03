"""SQLAlchemy User model with role-based access control."""

from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy import Enum as SQLAlchemyEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, BaseModelDict

if TYPE_CHECKING:
    from .audit import AuditLog

MAX_EMAIL_LENGTH: Final[int] = 255
MAX_PHONE_LENGTH: Final[int] = 20
MAX_VERIFICATION_CODE_LENGTH: Final[int] = 32
MAX_RESET_TOKEN_LENGTH: Final[int] = 64
MAX_OAUTH_ID_LENGTH: Final[int] = 255
MAX_OAUTH_PROVIDER_LENGTH: Final[int] = 50


class UserRole(StrEnum):
    """User role enumeration with hierarchical permissions.

    Roles inherit permissions from lower roles:
    - USER: Base role with basic permissions
    - MODERATOR: Has USER permissions + moderation capabilities
    - ADMIN: Has MODERATOR + USER permissions + administrative capabilities
    """

    USER = "user"
    MODERATOR = "moderator"
    ADMIN = "admin"

    def has_permission(self, required_role: "UserRole") -> bool:
        """Check if this role has the required permission level.

        Args:
            required_role: Role level to check against

        Returns:
            True if this role has sufficient permissions
        """
        role_levels = {
            UserRole.USER: 0,
            UserRole.MODERATOR: 1,
            UserRole.ADMIN: 2,
        }
        return role_levels[self] >= role_levels[required_role]


class UserModelDict(BaseModelDict):
    """User model serialized form."""

    email: str
    phone: str | None
    oauth_id: str | None
    oauth_provider: str | None
    role: str
    is_verified: bool
    is_active: bool
    verification_code: str | None
    verification_code_expires_at: str | None
    pending_email: str | None
    reset_token: str | None
    reset_token_expires_at: str | None
    failed_login_attempts: int
    last_failed_login_at: str | None


class User(Base):
    """User model with role-based access control."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(
        String(MAX_EMAIL_LENGTH),
        unique=True,
        nullable=False,
        index=True,
        comment="User's email address",
    )
    password_hash: Mapped[str] = mapped_column(
        Text, nullable=False, comment="Hashed password using Argon2id"
    )

    phone: Mapped[str | None] = mapped_column(
        String(MAX_PHONE_LENGTH),
        unique=True,
        nullable=True,
        index=True,
        comment="Phone number in E.164 format",
    )

    oauth_id: Mapped[str | None] = mapped_column(
        String(MAX_OAUTH_ID_LENGTH),
        nullable=True,
        index=True,
        comment="OAuth provider's unique identifier",
    )
    oauth_provider: Mapped[str | None] = mapped_column(
        String(MAX_OAUTH_PROVIDER_LENGTH),
        nullable=True,
        index=True,
        comment="OAuth provider name (e.g. google, github)",
    )

    role: Mapped[UserRole] = mapped_column(
        SQLAlchemyEnum(UserRole, name="user_role", create_constraint=True),
        nullable=False,
        comment="User role for authorization",
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="false",
        index=True,
        comment="Email verification status",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default="true",
        index=True,
        comment="Account status",
    )

    verification_code: Mapped[str | None] = mapped_column(
        String(MAX_VERIFICATION_CODE_LENGTH),
        nullable=True,
        index=True,
        comment="Email verification code",
    )
    verification_code_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Verification code expiry timestamp",
    )
    pending_email: Mapped[str | None] = mapped_column(
        String(MAX_EMAIL_LENGTH),
        nullable=True,
        index=True,
        comment="Pending email change address",
    )

    reset_token: Mapped[str | None] = mapped_column(
        String(MAX_RESET_TOKEN_LENGTH),
        nullable=True,
        index=True,
        comment="Password reset token",
    )
    reset_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Reset token expiry timestamp",
    )

    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default="0",
        comment="Number of consecutive failed login attempts",
    )
    last_failed_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
        comment="Timestamp of last failed login attempt",
    )

    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog",
        back_populates="user",
        lazy="noload",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index(
            "ix_users_oauth_lookup",
            "oauth_provider",
            "oauth_id",
            unique=True,
            postgresql_where=oauth_provider.isnot(None),
        ),
        Index(
            "ix_users_verification",
            "verification_code",
            "verification_code_expires_at",
            postgresql_where=verification_code.isnot(None),
        ),
        Index(
            "ix_users_reset_token",
            "reset_token",
            "reset_token_expires_at",
            postgresql_where=reset_token.isnot(None),
        ),
        Index(
            "ix_users_active_verified",
            "is_active",
            "is_verified",
        ),
        Index(
            "ix_users_email_is_verified",
            "email",
            "is_verified",
        ),
        Index(
            "ix_users_failed_login",
            "failed_login_attempts",
            "last_failed_login_at",
        ),
    )

    def __repr__(self) -> str:
        """Get string representation."""
        return f"<User {self.email}>"

    def dict(self) -> UserModelDict:
        """Convert model to dict with serialized values.

        Returns:
            Dictionary representation of the user
        """
        base_dict = super().dict()
        return UserModelDict(
            **base_dict,
            email=self.email,
            phone=self.phone,
            oauth_id=self.oauth_id,
            oauth_provider=self.oauth_provider,
            role=self.role.value,
            is_verified=self.is_verified,
            is_active=self.is_active,
            verification_code=self.verification_code,
            verification_code_expires_at=self.verification_code_expires_at.isoformat()
            if self.verification_code_expires_at
            else None,
            pending_email=self.pending_email,
            reset_token=self.reset_token,
            reset_token_expires_at=self.reset_token_expires_at.isoformat()
            if self.reset_token_expires_at
            else None,
            failed_login_attempts=self.failed_login_attempts,
            last_failed_login_at=self.last_failed_login_at.isoformat()
            if self.last_failed_login_at
            else None,
        )
