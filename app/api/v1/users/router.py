"""User management API endpoints."""
import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex

from fastapi import APIRouter, HTTPException, Request, status

from app.api.v1.dependencies import AuditRepo, CurrentUser, UserRepo
from app.core.config import settings
from app.core.errors import DuplicateError, NotFoundError
from app.core.security import get_password_hash
from app.models import User
from app.schemas import EmailRequest, UserCreate, UserResponse, UserUpdate
from app.services.email import EmailError, email_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> User:
    """Register a new user account.

    Args:
        request: FastAPI request
        user_in: User registration data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Created user

    Raises:
        HTTPException: If registration fails
    """
    try:
        # Check for existing email/phone
        try:
            await user_repo.get_by_email(user_in.email.lower())
            raise DuplicateError("Email already registered")
        except NotFoundError:
            pass

        if user_in.phone:
            try:
                await user_repo.get_by_phone(user_in.phone)
                raise DuplicateError("Phone number already registered")
            except NotFoundError:
                pass

        # Generate verification code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        # Create user
        user = await user_repo.create({
            "email": user_in.email.lower(),
            "phone": user_in.phone,
            "password_hash": get_password_hash(user_in.password),
            "verification_code": verification_code,
            "verification_code_expires_at": verification_expires,
        })

        # Log registration
        await audit_repo.create({
            "user_id": user.id,
            "action": "register",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "User registration successful",
        })

        # Send verification email
        try:
            await email_service.send_verification_email(
                to_email=user_in.email.lower(),
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            await audit_repo.create({
                "user_id": user.id,
                "action": "send_verification_email",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Failed to send verification email: {str(e)}",
            })

        return user

    except DuplicateError as e:
        logger.error("Registration failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Registration failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to register user",
        )


@router.post("/verify-email")
async def verify_email(
    request: Request,
    code: str,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Verify user's email address.

    Args:
        request: FastAPI request
        code: Verification code
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If verification fails
    """
    try:
        # Get user by verification code
        user = await user_repo.get_by_verification_code(code)

        # Check if code is expired
        if not user.verification_code_expires_at:
            raise NotFoundError("Invalid verification code")
        if user.verification_code_expires_at <= datetime.now(UTC):
            raise NotFoundError("Verification code expired")

        # Check if already verified
        if user.is_verified:
            raise NotFoundError("Email already verified")

        # Update user
        await user_repo.update(user.id, {
            "is_verified": True,
            "verification_code": None,
            "verification_code_expires_at": None,
        })

        # Log verification
        await audit_repo.create({
            "user_id": user.id,
            "action": "verify_email",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Email verified successfully",
        })

        return {"message": "Email verified successfully"}

    except NotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Email verification failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to verify email",
        )


@router.get("/me", response_model=UserResponse)
async def get_profile(current_user: CurrentUser) -> User:
    """Get current user's profile.

    Args:
        current_user: Current authenticated user

    Returns:
        User profile
    """
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    request: Request,
    user_update: UserUpdate,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> User:
    """Update current user's profile.

    Args:
        request: FastAPI request
        user_update: User update data
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Updated user profile

    Raises:
        HTTPException: If update fails
    """
    try:
        # Check phone uniqueness
        if user_update.phone:
            try:
                existing = await user_repo.get_by_phone(user_update.phone)
                if existing.id != current_user.id:
                    raise DuplicateError("Phone number already registered")
            except NotFoundError:
                pass

        # Prepare update data
        update_data = user_update.model_dump(exclude_unset=True)
        if "password" in update_data:
            update_data["password_hash"] = get_password_hash(update_data.pop("password"))

        # Update user
        user = await user_repo.update(current_user.id, update_data)

        # Log update
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "update_profile",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Profile updated successfully",
        })

        return user

    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Profile update failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update profile",
        )


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    request: Request,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> None:
    """Delete current user's account.

    Args:
        request: FastAPI request
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Raises:
        HTTPException: If deletion fails
    """
    try:
        # Log deletion first in case user deletion fails
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "delete_account",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Account deleted successfully",
        })

        # Delete user
        await user_repo.delete(current_user.id)

    except Exception as e:
        logger.error("Account deletion failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete account",
        )


@router.post("/me/verify-email/resend")
async def resend_verification(
    request: Request,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Resend verification email for current user.

    Args:
        request: FastAPI request
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If resend fails
    """
    try:
        # Check if already verified
        if current_user.is_verified:
            raise DuplicateError("Email already verified")

        # Generate new verification code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        # Update user with new verification code
        await user_repo.update(current_user.id, {
            "verification_code": verification_code,
            "verification_code_expires_at": verification_expires,
        })

        # Log resend attempt
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "resend_verification",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Verification email resent",
        })

        # Send verification email
        try:
            await email_service.send_verification_email(
                to_email=current_user.email,
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            await audit_repo.create({
                "user_id": current_user.id,
                "action": "send_verification_email",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Failed to send verification email: {str(e)}",
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email",
            )

        return {"message": "Verification email sent"}

    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except Exception as e:
        logger.error("Verification resend failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to resend verification email",
        )


@router.post("/verify-email/resend")
async def resend_verification_public(
    request: Request,
    email_in: EmailRequest,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Resend verification email (public endpoint).

    Args:
        request: FastAPI request
        email_in: Email request data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Note:
        Always returns success to prevent email enumeration
    """
    try:
        # Try to get unverified user by email
        try:
            user = await user_repo.get_by_email(email_in.email.lower())
            if user.is_verified:
                return {
                    "message": "If the email exists and is unverified, "
                    "a new verification email has been sent"
                }
        except NotFoundError:
            return {
                "message": "If the email exists and is unverified, "
                "a new verification email has been sent"
            }

        # Generate new verification code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        # Update user with new verification code
        await user_repo.update(user.id, {
            "verification_code": verification_code,
            "verification_code_expires_at": verification_expires,
        })

        # Log resend attempt
        await audit_repo.create({
            "user_id": user.id,
            "action": "resend_verification_public",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Verification email resent",
        })

        # Send verification email
        try:
            await email_service.send_verification_email(
                to_email=user.email,
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            await audit_repo.create({
                "user_id": user.id,
                "action": "send_verification_email",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Failed to send verification email: {str(e)}",
            })

        return {
            "message": "If the email exists and is unverified, "
            "a new verification email has been sent"
        }

    except Exception as e:
        logger.error("Public verification resend failed: %s", str(e))
        # Return success even on error to prevent email enumeration
        return {
            "message": "If the email exists and is unverified, "
            "a new verification email has been sent"
        }


@router.post("/me/email", response_model=dict[str, str])
async def request_email_change(
    request: Request,
    email_in: EmailRequest,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Request email address change.

    Args:
        request: FastAPI request
        email_in: Email request data
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If request fails
    """
    try:
        new_email = email_in.email.lower()

        # Check if new email is different
        if new_email == current_user.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New email must be different from current email",
            )

        # Check if email is already taken
        try:
            await user_repo.get_by_email(new_email)
            raise DuplicateError("Email already registered")
        except NotFoundError:
            pass

        # Generate verification code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        # Update user with verification code and pending email
        await user_repo.update(current_user.id, {
            "verification_code": verification_code,
            "verification_code_expires_at": verification_expires,
            "pending_email": new_email,
        })

        # Log email change request
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "request_email_change",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": f"Requested email change to {new_email}",
        })

        # Send verification email
        try:
            await email_service.send_verification_email(
                to_email=new_email,
                verification_code=verification_code,
            )
        except EmailError as e:
            logger.error("Email change request failed: %s", e.detail)
            await audit_repo.create({
                "user_id": current_user.id,
                "action": "send_verification_email",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Failed to send verification email: {e.detail}",
            })
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unable to send verification email. Please try again later.",
            )

        return {"message": "Verification email sent to new address"}

    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Email change request failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to request email change",
        )


@router.post("/me/email/verify", response_model=UserResponse)
async def verify_email_change(
    request: Request,
    code: str,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> User:
    """Verify and complete email address change.

    Args:
        request: FastAPI request
        code: Verification code
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Updated user profile

    Raises:
        HTTPException: If verification fails
    """
    try:
        # Validate pending email change
        if not current_user.pending_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No pending email change",
            )

        # Validate verification code
        if not current_user.verification_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No verification code found",
            )
        if current_user.verification_code != code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code",
            )
        if not current_user.verification_code_expires_at or current_user.verification_code_expires_at < datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification code expired",
            )

        # Check if email is still available
        try:
            existing = await user_repo.get_by_email(current_user.pending_email)
            if existing.id != current_user.id:
                raise DuplicateError("Email already taken")
        except NotFoundError:
            pass

        old_email = current_user.email

        # Update user email
        user = await user_repo.update(current_user.id, {
            "email": current_user.pending_email,
            "pending_email": None,
            "verification_code": None,
            "verification_code_expires_at": None,
            "is_verified": True,
        })

        # Log email change
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "verify_email_change",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": f"Changed email from {old_email} to {user.email}",
        })

        # Send notification to old email
        try:
            await email_service.send_email_change_notification(
                to_email=old_email,
                new_email=user.email,
            )
        except Exception as e:
            logger.error("Failed to send change notification: %s", str(e))
            await audit_repo.create({
                "user_id": current_user.id,
                "action": "send_email_change_notification",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Failed to send change notification: {str(e)}",
            })

        return user

    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Email change verification failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to verify email change",
        )
