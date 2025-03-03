"""User repository implementation."""

from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFoundError
from app.models.user import User, UserRole
from app.repositories.base import BaseRepository
from app.schemas.user import OAuthUserCreate

MAX_USERS_PER_PAGE: Final[int] = 50
DEFAULT_USERS_PER_PAGE: Final[int] = 20
DEFAULT_USER_ROLE: Final[UserRole] = UserRole.USER


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

    async def get_by_oauth_id(self, provider: str, oauth_id: str) -> User:
        """Get user by OAuth ID.

        Args:
            provider: OAuth provider name
            oauth_id: Provider's user ID

        Returns:
            User instance

        Raises:
            NotFoundError: If user not found
        """
        assert provider, "Provider cannot be empty"
        assert oauth_id, "OAuth ID cannot be empty"

        query = select(User).where(
            User.oauth_provider == provider,
            User.oauth_id == oauth_id,
        )
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        return user

    async def get_all_by_role(
        self,
        role: UserRole,
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
        assert role is not None, "Role cannot be None"
        assert offset >= 0, "Offset must be non-negative"
        assert 0 < limit <= MAX_USERS_PER_PAGE, (
            f"Limit must be between 1 and {MAX_USERS_PER_PAGE}"
        )

        query = select(User).where(User.role == role).offset(offset).limit(limit)
        result = await self._session.execute(query)
        return list(result.scalars().all())

    async def create_oauth_user(
        self,
        email: str,
        provider: str,
        oauth_id: str,
        *,
        is_verified: bool = True,
        role: UserRole = DEFAULT_USER_ROLE,
    ) -> User:
        """Create a new user from OAuth login.

        Args:
            email: User's email address
            provider: OAuth provider name
            oauth_id: Provider's user ID
            is_verified: Whether email is verified (default True for OAuth)
            role: User role (defaults to UserRole.USER)

        Returns:
            Created user instance

        Raises:
            DuplicateError: If user already exists
            DatabaseError: For other database errors
        """

        oauth_user = OAuthUserCreate(
            email=email,
            oauth_provider=provider,
            oauth_id=oauth_id,
            is_verified=is_verified,
        )

        create_data = oauth_user.model_dump()
        create_data.update(
            {
                "is_active": True,
                "password_hash": "",
                "role": role,
            }
        )

        return await self.create(create_data)

    async def link_oauth_account(
        self,
        user_id: UUID,
        provider: str,
        oauth_id: str,
    ) -> User:
        """Link an OAuth account to existing user.

        Args:
            user_id: User's UUID
            provider: OAuth provider name
            oauth_id: Provider's user ID

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
            DuplicateError: If OAuth account already linked
            DatabaseError: For other database errors
        """
        assert provider, "Provider cannot be empty"
        assert oauth_id, "OAuth ID cannot be empty"

        # Get user first to ensure they exist
        user = await self.get_by_id(user_id)

        # Update OAuth fields if not already set
        if not user.oauth_provider and not user.oauth_id:
            user.oauth_provider = provider
            user.oauth_id = oauth_id
            await self._session.commit()
            await self._session.refresh(user)

        return user

    async def get_provider_stats(self) -> dict[str, int]:
        """Get count of users by OAuth provider.

        Returns:
            Dictionary mapping provider names to user counts
        """
        query = (
            select(User.oauth_provider, func.count(User.id))
            .where(User.oauth_provider.is_not(None))
            .group_by(User.oauth_provider)
        )
        result = await self._session.execute(query)

        stats = {
            provider: count for provider, count in result.all() if provider is not None
        }
        return stats

    async def increment_failed_login(self, user_id: UUID) -> User:
        """Increment failed login attempts for user.

        Args:
            user_id: User's UUID

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
        """
        query = (
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=User.failed_login_attempts + 1,
                last_failed_login_at=datetime.now(UTC),
            )
            .returning(User)
        )
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        await self._session.commit()
        return user

    async def reset_failed_login(self, user_id: UUID) -> User:
        """Reset failed login attempts for user.

        Args:
            user_id: User's UUID

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
        """
        query = (
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=0,
                last_failed_login_at=None,
            )
            .returning(User)
        )
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        await self._session.commit()
        return user

    async def disable_account(self, user_id: UUID) -> User:
        """Disable user account.

        Args:
            user_id: User's UUID

        Returns:
            Updated user instance

        Raises:
            NotFoundError: If user not found
        """
        query = (
            update(User)
            .where(User.id == user_id)
            .values(is_active=False)
            .returning(User)
        )
        result = await self._session.execute(query)
        user = result.scalar_one_or_none()

        if user is None:
            raise NotFoundError("User not found")

        await self._session.commit()
        return user
