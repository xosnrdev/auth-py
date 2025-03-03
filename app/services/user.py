"""User management service for registration and profile operations."""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from uuid import UUID

from fastapi import Request

from app.core.config import settings
from app.core.errors import DuplicateError, NotFoundError, UserError
from app.core.security import get_password_hash, verify_password
from app.models.user import User, UserRole
from app.repositories import AuditLogRepository, UserRepository
from app.schemas import UserCreate, UserUpdate
from app.schemas.audit import AuditLogCreate
from app.services.audit import AuditService
from app.services.email import EmailError, email_service
from app.services.token import token_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)


class UserService:
    """User management service for registration and profile operations.

    This service handles:
    - User registration with email verification
    - Profile management (update, delete)
    - Email verification and change
    - Account security
    - User administration (list, get, update, delete)
    - Role management
    """

    def __init__(
        self,
        user_repo: UserRepository,
        audit_repo: AuditLogRepository,
    ) -> None:
        """Initialize user service.

        Args:
            user_repo: User repository for user operations
            audit_repo: Audit repository for logging user events
        """
        self._user_repo = user_repo
        self._audit_repo = audit_repo

    async def register(
        self,
        request: Request,
        user_data: UserCreate,
    ) -> User:
        """Register new user with email verification.

        Args:
            request: FastAPI request
            user_data: User registration data

        Returns:
            Created user

        Raises:
            UserError: If registration fails
            DuplicateError: If email/phone already exists
        """
        try:
            try:
                await self._user_repo.get_by_email(user_data.email.lower())
                raise DuplicateError("Email already registered")
            except NotFoundError:
                pass

            if user_data.phone:
                try:
                    await self._user_repo.get_by_phone(user_data.phone)
                    raise DuplicateError("Phone number already registered")
                except NotFoundError:
                    pass

            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            create_data = user_data.model_dump()
            create_data.update(
                {
                    "password_hash": get_password_hash(create_data.pop("password")),
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                }
            )

            user = await self._user_repo.create(create_data)

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="register",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="User registration successful",
                )
            )

            try:
                await email_service.send_verification_email(
                    to_email=user_data.email.lower(),
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user.id,
                        action="send_verification_email",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed to send verification email: {str(e)}",
                    )
                )

            return user

        except DuplicateError:
            raise
        except Exception as e:
            logger.error("Registration failed: %s", str(e))
            raise UserError("Failed to register user")

    async def verify_email(
        self,
        request: Request,
        code: str,
    ) -> None:
        """Verify user's email address.

        Args:
            request: FastAPI request
            code: Verification code

        Raises:
            UserError: If verification fails
        """
        try:
            user = await self._user_repo.get_by_verification_code(code)

            if not user.verification_code_expires_at:
                raise NotFoundError("Invalid verification code")
            if user.verification_code_expires_at <= datetime.now(UTC):
                raise NotFoundError("Verification code expired")

            if user.is_verified:
                raise NotFoundError("Email already verified")

            await self._user_repo.update(
                user.id,
                {
                    "is_verified": True,
                    "verification_code": None,
                    "verification_code_expires_at": None,
                },
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="verify_email",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Email verified successfully",
                )
            )

        except NotFoundError as e:
            raise UserError(str(e))
        except Exception as e:
            logger.error("Email verification failed: %s", str(e))
            raise UserError("Failed to verify email")

    async def update_profile(
        self,
        request: Request,
        user_id: UUID,
        data: UserUpdate,
    ) -> User:
        """Update user profile.

        Args:
            request: FastAPI request
            user_id: User ID
            data: Profile update data

        Returns:
            Updated user

        Raises:
            UserError: If update fails
            DuplicateError: If phone number already exists
        """
        try:
            # Get current user first
            current_user = await self._user_repo.get_by_id(user_id)

            if data.phone:
                # Verify new phone is different from current
                if data.phone == current_user.phone:
                    raise UserError(
                        "New phone number must be different from current phone number"
                    )

                try:
                    existing = await self._user_repo.get_by_phone(data.phone)
                    if existing.id != user_id:
                        raise DuplicateError("Phone number already registered")
                except NotFoundError:
                    pass

            update_data = data.model_dump(exclude_unset=True)
            password_updated = False
            if "password" in update_data:
                # Verify new password is different from current
                if verify_password(update_data["password"], current_user.password_hash):
                    raise UserError(
                        "New password must be different from current password"
                    )

                password_updated = True
                update_data["password_hash"] = get_password_hash(
                    update_data.pop("password"),
                )

            user = await self._user_repo.update(user_id, update_data)

            if password_updated:
                await token_service.revoke_all_user_tokens(user_id.hex)

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user_id,
                    action="update_profile",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Profile updated successfully",
                )
            )

            return user

        except DuplicateError:
            raise
        except UserError:
            raise
        except Exception as e:
            logger.error("Profile update failed: %s", str(e))
            raise UserError("Failed to update profile")

    async def delete_profile(
        self,
        request: Request,
        user_id: UUID,
    ) -> None:
        """Delete user account.

        Args:
            request: FastAPI request
            user_id: User ID

        Raises:
            UserError: If deletion fails
        """
        try:
            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user_id,
                    action="delete_account",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Account deleted successfully",
                )
            )

            await self._user_repo.delete(user_id)

        except Exception as e:
            logger.error("Account deletion failed: %s", str(e))
            raise UserError("Failed to delete account")

    async def request_email_change(
        self,
        request: Request,
        user_id: UUID,
        new_email: str,
    ) -> None:
        """Request email address change.

        Args:
            request: FastAPI request
            user_id: User ID
            new_email: New email address

        Raises:
            UserError: If request fails
            DuplicateError: If email already exists
        """
        try:
            user = await self._user_repo.get_by_id(user_id)

            if new_email.lower() == user.email:
                raise UserError("New email must be different from current email")

            try:
                await self._user_repo.get_by_email(new_email.lower())
                raise DuplicateError("Email already registered")
            except NotFoundError:
                pass

            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            await self._user_repo.update(
                user_id,
                {
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                    "pending_email": new_email.lower(),
                },
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user_id,
                    action="request_email_change",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Requested email change to {new_email}",
                )
            )

            try:
                await email_service.send_verification_email(
                    to_email=new_email.lower(),
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user_id,
                        action="send_verification_email",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed to send verification email: {str(e)}",
                    )
                )
                raise UserError("Unable to send verification email")

        except DuplicateError:
            raise
        except UserError:
            raise
        except Exception as e:
            logger.error("Email change request failed: %s", str(e))
            raise UserError("Failed to request email change")

    async def verify_email_change(
        self,
        request: Request,
        user_id: UUID,
        code: str,
    ) -> User:
        """Verify and complete email address change.

        Args:
            request: FastAPI request
            user_id: User ID
            code: Verification code

        Returns:
            Updated user

        Raises:
            UserError: If verification fails
            DuplicateError: If email already taken
        """
        try:
            user = await self._user_repo.get_by_id(user_id)

            if not user.pending_email:
                raise UserError("No pending email change")

            if not user.verification_code:
                raise UserError("No verification code found")
            if user.verification_code != code:
                raise UserError("Invalid verification code")
            if (
                not user.verification_code_expires_at
                or user.verification_code_expires_at < datetime.now(UTC)
            ):
                raise UserError("Verification code expired")

            try:
                existing = await self._user_repo.get_by_email(user.pending_email)
                if existing.id != user_id:
                    raise DuplicateError("Email already taken")
            except NotFoundError:
                pass

            old_email = user.email

            updated_user = await self._user_repo.update(
                user_id,
                {
                    "email": user.pending_email,
                    "pending_email": None,
                    "verification_code": None,
                    "verification_code_expires_at": None,
                    "is_verified": True,
                },
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user_id,
                    action="verify_email_change",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Email changed to {updated_user.email}",
                )
            )

            try:
                await email_service.send_email_change_notification(
                    to_email=old_email,
                    new_email=updated_user.email,
                )
            except EmailError as e:
                logger.error("Failed to send change notification: %s", str(e))
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user_id,
                        action="send_email_change_notification",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed to send change notification: {str(e)}",
                    )
                )

            return updated_user

        except DuplicateError:
            raise
        except UserError:
            raise
        except Exception as e:
            logger.error("Email change verification failed: %s", str(e))
            raise UserError("Failed to verify email change")

    async def resend_verification(
        self,
        request: Request,
        user_id: UUID,
    ) -> None:
        """Resend verification email for authenticated user.

        Args:
            request: FastAPI request
            user_id: User ID

        Raises:
            UserError: If resend fails
        """
        try:
            user = await self._user_repo.get_by_id(user_id)

            if user.is_verified:
                raise UserError("Email already verified")

            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            await self._user_repo.update(
                user_id,
                {
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                },
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user_id,
                    action="resend_verification",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Verification email resent",
                )
            )

            try:
                await email_service.send_verification_email(
                    to_email=user.email,
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user_id,
                        action="send_verification_email",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed to send verification email: {str(e)}",
                    )
                )
                raise UserError("Failed to send verification email")

        except UserError:
            raise
        except Exception as e:
            logger.error("Verification resend failed: %s", str(e))
            raise UserError("Failed to resend verification email")

    async def resend_verification_public(
        self,
        request: Request,
        email: str,
    ) -> None:
        """Resend verification email (public endpoint).

        Args:
            request: FastAPI request
            email: User email

        Note:
            Always returns silently to prevent email enumeration
        """
        try:
            try:
                user = await self._user_repo.get_by_email(email.lower())
                if user.is_verified:
                    return
            except NotFoundError:
                return

            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            await self._user_repo.update(
                user.id,
                {
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                },
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=user.id,
                    action="resend_verification_public",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details="Verification email resent",
                )
            )

            try:
                await email_service.send_verification_email(
                    to_email=user.email,
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                audit_service = AuditService(self._audit_repo)
                await audit_service.create_log(
                    AuditLogCreate(
                        user_id=user.id,
                        action="send_verification_email",
                        ip_address=get_client_ip(request),
                        user_agent=request.headers.get("user-agent", ""),
                        details=f"Failed to send verification email: {str(e)}",
                    )
                )

        except Exception as e:
            logger.error("Public verification resend failed: %s", str(e))

    async def list_users_by_role(
        self,
        role: UserRole,
        skip: int = 0,
        limit: int = 100,
    ) -> list[User]:
        """List users with specific role.

        Args:
            role: Role to filter by
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of users with the role
        """
        return await self._user_repo.get_all_by_role(role, offset=skip, limit=limit)

    async def list_users(self, skip: int = 0, limit: int = 100) -> list[User]:
        """List all users with pagination.

        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return

        Returns:
            List of users
        """
        return await self._user_repo.get_all(offset=skip, limit=limit)

    async def get_user(self, user_id: UUID) -> User:
        """Get specific user details.

        Args:
            user_id: User ID to get

        Returns:
            User details

        Raises:
            NotFoundError: If user not found
        """
        return await self._user_repo.get_by_id(user_id)

    async def admin_update_user(
        self,
        request: Request,
        user_id: UUID,
        user_data: UserUpdate,
        admin_user: User,
    ) -> User:
        """Update user as admin.

        Args:
            request: FastAPI request
            user_id: User ID to update
            user_data: User update data
            admin_user: Admin user performing the update

        Returns:
            Updated user

        Raises:
            NotFoundError: If user not found
            UserError: If update fails
        """
        try:
            user = await self._user_repo.get_by_id(user_id)

            update_data = user_data.model_dump(exclude_unset=True)
            password_updated = False

            if "password" in update_data:
                update_data["password_hash"] = get_password_hash(
                    update_data.pop("password")
                )
                password_updated = True

            updated_user = await self._user_repo.update(user_id, update_data)

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=admin_user.id,
                    action="admin_update_user",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Updated user {user.email}",
                )
            )

            if password_updated:
                await token_service.revoke_all_user_tokens(user_id.hex)

            return updated_user

        except Exception as e:
            logger.error("Admin user update failed: %s", str(e))
            raise UserError("Failed to update user")

    async def admin_delete_user(
        self,
        request: Request,
        user_id: UUID,
        admin_user: User,
    ) -> None:
        """Delete user as admin.

        Args:
            request: FastAPI request
            user_id: User ID to delete
            admin_user: Admin user performing the deletion

        Raises:
            NotFoundError: If user not found
            UserError: If deletion fails
        """
        user = await self._user_repo.get_by_id(user_id)
        user_email = user.email

        await self._user_repo.delete(user_id)

        audit_service = AuditService(self._audit_repo)
        await audit_service.create_log(
            AuditLogCreate(
                user_id=admin_user.id,
                action="delete_user",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Deleted user {user_email}",
            )
        )

    async def update_user_role(
        self,
        request: Request,
        user_id: UUID,
        role: UserRole,
        admin_user: User,
    ) -> User:
        """Update user role as admin.

        Args:
            request: FastAPI request
            user_id: User ID to update
            role: New role to assign
            admin_user: Admin user performing the update

        Returns:
            Updated user

        Raises:
            NotFoundError: If user not found
            UserError: If role update fails
        """
        user = await self._user_repo.get_by_id(user_id)

        updated_user = await self._user_repo.update(user_id, {"role": role})

        audit_service = AuditService(self._audit_repo)
        await audit_service.create_log(
            AuditLogCreate(
                user_id=admin_user.id,
                action="update_role",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Updated role for user {user.email} to {role.value}",
            )
        )

        return updated_user

    async def remove_user_role(
        self,
        request: Request,
        user_id: UUID,
        role: UserRole,
        admin_user: User,
    ) -> User:
        """Remove role from user as admin.

        Args:
            request: FastAPI request
            user_id: User ID to update
            role: Role to remove
            admin_user: Admin user performing the update

        Returns:
            Updated user

        Raises:
            NotFoundError: If user not found
            UserError: If role removal fails
        """
        user = await self._user_repo.get_by_id(user_id)

        if role == UserRole.USER:
            return user

        if user.role == role:
            updated_user = await self._user_repo.update(
                user_id, {"role": UserRole.USER}
            )

            audit_service = AuditService(self._audit_repo)
            await audit_service.create_log(
                AuditLogCreate(
                    user_id=admin_user.id,
                    action="remove_role",
                    ip_address=get_client_ip(request),
                    user_agent=request.headers.get("user-agent", ""),
                    details=f"Removed role {role} from user {user.email}",
                )
            )

            return updated_user

        return user

    async def list_roles(self) -> list[str]:
        """List all available user roles.

        Returns:
            List of role values
        """
        return [role.value for role in UserRole]
