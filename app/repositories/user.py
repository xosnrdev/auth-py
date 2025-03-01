"""User repository implementation."""

from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import DatabaseError, NotFoundError
from app.models.user import User
from app.repositories.base import BaseRepository

# Constants
MAX_USERS_PER_PAGE: Final[int] = 50
DEFAULT_USERS_PER_PAGE: Final[int] = 20


class UserRepository(BaseRepository[User]):
    """User repository with specialized user operations."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize user repository.

        Args:
            session: SQLAlchemy async session
        """
        super().__init__(session, User)

    async def get_by_email(self, email: str) -> User:
        """Get user by email.

        Args:
            email: User's email address

        Returns:
            User instance

        Raises:
            NotFoundError: If user not found
        """
        assert email, "Email cannot be empty"

        query = select(User).where(User.email == email)
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        return user

    async def get_by_phone(self, phone: str) -> User:
        """Get user by phone number.

        Args:
            phone: User's phone number

        Returns:
            User instance

        Raises:
            NotFoundError: If user not found
        """
        assert phone, "Phone number cannot be empty"

        query = select(User).where(User.phone == phone)
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        return user

    async def get_by_verification_code(self, code: str) -> User:
        """Get user by verification code.

        Args:
            code: Email verification code

        Returns:
            User instance

        Raises:
            NotFoundError: If user not found or code expired
        """
        assert code, "Verification code cannot be empty"

        query = select(User).where(
            User.verification_code == code,
            User.verification_code_expires_at > datetime.now(UTC),
        )
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("Invalid or expired verification code")

        return user

    async def get_by_reset_token(self, token: str) -> User:
        """Get user by password reset token.

        Args:
            token: Password reset token

        Returns:
            User instance

        Raises:
            NotFoundError: If user not found or token expired
        """
        assert token, "Reset token cannot be empty"

        query = select(User).where(
            User.reset_token == token,
            User.reset_token_expires_at > datetime.now(UTC),
        )
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("Invalid or expired reset token")

        return user

    async def get_by_social_id(self, provider: str, social_id: str) -> User:
        """Get user by social login ID.

        Args:
            provider: OAuth provider name
            social_id: Provider's user ID

        Returns:
            User instance

        Raises:
            NotFoundError: If user not found
        """
        assert provider, "Provider cannot be empty"
        assert social_id, "Social ID cannot be empty"

        query = select(User).where(User.social_id[provider].astext == social_id)
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        return user

    async def get_all_by_role(
        self,
        role: str,
        *,
        offset: int = 0,
        limit: int = DEFAULT_USERS_PER_PAGE,
    ) -> list[User]:
        """Get all users with specific role.

        Args:
            role: Role to filter by
            offset: Number of users to skip
            limit: Maximum number of users to return

        Returns:
            List of users with the role
        """
        assert role, "Role cannot be empty"
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_USERS_PER_PAGE, (
            f"Limit must be between 1 and {MAX_USERS_PER_PAGE}"
        )

        query = (
            select(User)
            .where(User.roles.contains([role]))
            .offset(offset)
            .limit(limit)
        )
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def create_social_user(
        self,
        email: str,
        provider: str,
        social_id: str,
        *,
        is_verified: bool = True,
        name: str | None = None,
        picture: str | None = None,
        locale: str | None = None,
    ) -> User:
        """Create a new user from social login.

        Args:
            email: User's email address
            provider: OAuth provider name
            social_id: Provider's user ID
            is_verified: Whether email is verified (default True for social)
            name: User's display name
            picture: User's profile picture URL
            locale: User's preferred locale

        Returns:
            Created user instance

        Raises:
            DuplicateError: If user already exists
            DatabaseError: For other database errors
        """
        assert email, "Email cannot be empty"
        assert provider, "Provider cannot be empty"
        assert social_id, "Social ID cannot be empty"

        # Create user with social ID
        return await self.create({
            "email": email,
            "is_active": True,
            "is_verified": is_verified,
            "password_hash": "",  # Empty for social users
            "name": name,
            "picture": picture,
            "locale": locale,
            "social_id": {provider: social_id},
        })

    async def link_social_account(
        self,
        user_id: UUID,
        provider: str,
        social_id: str,
    ) -> User:
        """Link a social account to existing user.

        Args:
            user_id: User's UUID
            provider: OAuth provider name
            social_id: Provider's user ID

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
            DuplicateError: If social account already linked
            DatabaseError: For other database errors
        """
        assert provider, "Provider cannot be empty"
        assert social_id, "Social ID cannot be empty"

        # Get user first to ensure they exist
        user = await self.get_by_id(user_id)

        # Update social ID if not already set
        if provider not in user.social_id:
            user.social_id[provider] = social_id
            await self._session.commit()
            await self._session.refresh(user)

        return user

    async def get_provider_stats(self) -> dict[str, int]:
        """Get count of users per social provider.

        Returns:
            Dictionary mapping provider names to user counts

        Raises:
            DatabaseError: For database errors
        """
        stats: dict[str, int] = {}

        try:
            # Count users with Google social ID
            google_count = await self._session.scalar(
                select(func.count(User.id))
                .where(User.social_id["google"].isnot(None))
            ) or 0
            stats["google_users"] = google_count

            # Count users with Apple social ID
            apple_count = await self._session.scalar(
                select(func.count(User.id))
                .where(User.social_id["apple"].isnot(None))
            ) or 0
            stats["apple_users"] = apple_count

            return stats

        except Exception as e:
            raise DatabaseError(f"Failed to get provider stats: {str(e)}") from e
