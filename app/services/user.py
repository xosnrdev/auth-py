"""User management service for registration and profile operations."""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from uuid import UUID

from fastapi import Request

from app.core.config import settings
from app.core.errors import DuplicateError, NotFoundError, UserError
from app.core.security import get_password_hash
from app.models import User
from app.repositories import AuditLogRepository, UserRepository
from app.schemas import UserCreate, UserUpdate
from app.services.email import EmailError, email_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)


class UserService:
    """User management service for registration and profile operations.

    This service handles:
    - User registration with email verification
    - Profile management (update, delete)
    - Email verification and change
    - Account security
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
            # Check for existing email/phone
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

            # Generate verification code
            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            # Create user
            user = await self._user_repo.create(
                {
                    "email": user_data.email.lower(),
                    "phone": user_data.phone,
                    "password_hash": get_password_hash(user_data.password),
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                }
            )

            # Log registration
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "register",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "User registration successful",
                }
            )

            # Send verification email
            try:
                await email_service.send_verification_email(
                    to_email=user_data.email.lower(),
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                await self._audit_repo.create(
                    {
                        "user_id": user.id,
                        "action": "send_verification_email",
                        "ip_address": get_client_ip(request),
                        "user_agent": request.headers.get("user-agent", ""),
                        "details": f"Failed to send verification email: {str(e)}",
                    }
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
            # Get user by verification code
            user = await self._user_repo.get_by_verification_code(code)

            # Check if code is expired
            if not user.verification_code_expires_at:
                raise NotFoundError("Invalid verification code")
            if user.verification_code_expires_at <= datetime.now(UTC):
                raise NotFoundError("Verification code expired")

            # Check if already verified
            if user.is_verified:
                raise NotFoundError("Email already verified")

            # Update user
            await self._user_repo.update(
                user.id,
                {
                    "is_verified": True,
                    "verification_code": None,
                    "verification_code_expires_at": None,
                },
            )

            # Log verification
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "verify_email",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Email verified successfully",
                }
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
            # Check phone uniqueness
            if data.phone:
                try:
                    existing = await self._user_repo.get_by_phone(data.phone)
                    if existing.id != user_id:
                        raise DuplicateError("Phone number already registered")
                except NotFoundError:
                    pass

            # Prepare update data
            update_data = data.model_dump(exclude_unset=True)
            if "password" in update_data:
                update_data["password_hash"] = get_password_hash(
                    update_data.pop("password"),
                )

            # Update user
            user = await self._user_repo.update(user_id, update_data)

            # Log update
            await self._audit_repo.create(
                {
                    "user_id": user_id,
                    "action": "update_profile",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Profile updated successfully",
                }
            )

            return user

        except DuplicateError:
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
            # Log deletion first in case user deletion fails
            await self._audit_repo.create(
                {
                    "user_id": user_id,
                    "action": "delete_account",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Account deleted successfully",
                }
            )

            # Delete user
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
            # Get current user
            user = await self._user_repo.get_by_id(user_id)

            # Check if new email is different
            if new_email.lower() == user.email:
                raise UserError("New email must be different from current email")

            # Check if email is already taken
            try:
                await self._user_repo.get_by_email(new_email.lower())
                raise DuplicateError("Email already registered")
            except NotFoundError:
                pass

            # Generate verification code
            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            # Update user with verification code and pending email
            await self._user_repo.update(
                user_id,
                {
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                    "pending_email": new_email.lower(),
                },
            )

            # Log email change request
            await self._audit_repo.create(
                {
                    "user_id": user_id,
                    "action": "request_email_change",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": f"Requested email change to {new_email}",
                }
            )

            # Send verification email
            try:
                await email_service.send_verification_email(
                    to_email=new_email.lower(),
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                await self._audit_repo.create(
                    {
                        "user_id": user_id,
                        "action": "send_verification_email",
                        "ip_address": get_client_ip(request),
                        "user_agent": request.headers.get("user-agent", ""),
                        "details": f"Failed to send verification email: {str(e)}",
                    }
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
            # Get current user
            user = await self._user_repo.get_by_id(user_id)

            # Validate pending email change
            if not user.pending_email:
                raise UserError("No pending email change")

            # Validate verification code
            if not user.verification_code:
                raise UserError("No verification code found")
            if user.verification_code != code:
                raise UserError("Invalid verification code")
            if (
                not user.verification_code_expires_at
                or user.verification_code_expires_at < datetime.now(UTC)
            ):
                raise UserError("Verification code expired")

            # Check if email is still available
            try:
                existing = await self._user_repo.get_by_email(user.pending_email)
                if existing.id != user_id:
                    raise DuplicateError("Email already taken")
            except NotFoundError:
                pass

            old_email = user.email

            # Update user email
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

            # Log email change
            await self._audit_repo.create(
                {
                    "user_id": user_id,
                    "action": "verify_email_change",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": f"Changed email from {old_email} to {updated_user.email}",
                }
            )

            # Send notification to old email
            try:
                await email_service.send_email_change_notification(
                    to_email=old_email,
                    new_email=updated_user.email,
                )
            except EmailError as e:
                logger.error("Failed to send change notification: %s", str(e))
                await self._audit_repo.create(
                    {
                        "user_id": user_id,
                        "action": "send_email_change_notification",
                        "ip_address": get_client_ip(request),
                        "user_agent": request.headers.get("user-agent", ""),
                        "details": f"Failed to send change notification: {str(e)}",
                    }
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
            # Get current user
            user = await self._user_repo.get_by_id(user_id)

            # Check if already verified
            if user.is_verified:
                raise UserError("Email already verified")

            # Generate new verification code
            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            # Update user with new verification code
            await self._user_repo.update(
                user_id,
                {
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                },
            )

            # Log resend attempt
            await self._audit_repo.create(
                {
                    "user_id": user_id,
                    "action": "resend_verification",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Verification email resent",
                }
            )

            # Send verification email
            try:
                await email_service.send_verification_email(
                    to_email=user.email,
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                await self._audit_repo.create(
                    {
                        "user_id": user_id,
                        "action": "send_verification_email",
                        "ip_address": get_client_ip(request),
                        "user_agent": request.headers.get("user-agent", ""),
                        "details": f"Failed to send verification email: {str(e)}",
                    }
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
            # Try to get unverified user by email
            try:
                user = await self._user_repo.get_by_email(email.lower())
                if user.is_verified:
                    return
            except NotFoundError:
                return

            # Generate new verification code
            verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
            verification_expires = datetime.now(UTC) + timedelta(
                seconds=settings.VERIFICATION_CODE_TTL_SECS,
            )

            # Update user with new verification code
            await self._user_repo.update(
                user.id,
                {
                    "verification_code": verification_code,
                    "verification_code_expires_at": verification_expires,
                },
            )

            # Log resend attempt
            await self._audit_repo.create(
                {
                    "user_id": user.id,
                    "action": "resend_verification_public",
                    "ip_address": get_client_ip(request),
                    "user_agent": request.headers.get("user-agent", ""),
                    "details": "Verification email resent",
                }
            )

            # Send verification email
            try:
                await email_service.send_verification_email(
                    to_email=user.email,
                    verification_code=verification_code,
                )
            except EmailError as e:
                logger.error("Failed to send verification email: %s", str(e))
                await self._audit_repo.create(
                    {
                        "user_id": user.id,
                        "action": "send_verification_email",
                        "ip_address": get_client_ip(request),
                        "user_agent": request.headers.get("user-agent", ""),
                        "details": f"Failed to send verification email: {str(e)}",
                    }
                )

        except Exception as e:
            logger.error("Public verification resend failed: %s", str(e))
            # Return silently to prevent email enumeration
