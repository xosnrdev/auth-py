"""User management API endpoints."""
import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.v1.dependencies import CurrentUser, DBSession
from app.core.config import settings
from app.core.security import get_password_hash
from app.models import AuditLog, User
from app.schemas import EmailRequest, UserCreate, UserResponse, UserUpdate
from app.services.email import EmailError, email_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    db: DBSession,
) -> User:
    """Register a new user account."""
    try:
        stmt = select(User).where(User.email == user_in.email.lower())
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        assert not existing, "Email already registered"

        if user_in.phone:
            stmt = select(User).where(User.phone == user_in.phone)
            result = await db.execute(stmt)
            existing = result.scalar_one_or_none()
            assert not existing, "Phone number already registered"

        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        user = User(
            email=user_in.email.lower(),
            phone=user_in.phone,
            password_hash=get_password_hash(user_in.password),
            verification_code=verification_code,
            verification_code_expires_at=verification_expires,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        audit_log = AuditLog(
            user_id=user.id,
            action="register",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="User registration successful",
        )
        db.add(audit_log)
        await db.commit()

        try:
            await email_service.send_verification_email(
                to_email=user_in.email.lower(),
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            audit_log = AuditLog(
                user_id=user.id,
                action="send_verification_email",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Failed to send verification email: {str(e)}",
            )
            db.add(audit_log)
            await db.commit()

        return user

    except AssertionError as e:
        logger.error("Registration failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.post("/verify-email")
async def verify_email(
    request: Request,
    code: str,
    db: DBSession,
) -> dict[str, str]:
    """Verify user's email address."""
    try:
        stmt = select(User).where(
            User.verification_code == code,
            User.verification_code_expires_at > datetime.now(UTC),
            User.is_verified.is_(False),
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        assert user, "Invalid or expired verification code"

        user.is_verified = True
        user.verification_code = None
        user.verification_code_expires_at = None

        audit_log = AuditLog(
            user_id=user.id,
            action="verify_email",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Email verified successfully",
        )
        db.add(audit_log)
        await db.commit()

        return {"message": "Email verified successfully"}

    except AssertionError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/me", response_model=UserResponse)
async def get_profile(current_user: CurrentUser) -> User:
    """Get current user's profile."""
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    request: Request,
    user_update: UserUpdate,
    current_user: CurrentUser,
    db: DBSession,
) -> User:
    """Update current user's profile."""
    if user_update.phone:
        stmt = select(User).where(
            User.phone == user_update.phone,
            User.id != current_user.id,
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Phone number already registered",
            )

    for field, value in user_update.model_dump(exclude_unset=True).items():
        if field == "password":
            current_user.password_hash = get_password_hash(value)
        else:
            setattr(current_user, field, value)

    audit_log = AuditLog(
        user_id=current_user.id,
        action="update_profile",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Profile updated successfully",
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(current_user)

    return current_user


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> None:
    """Delete current user's account."""
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_account",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Account deleted successfully",
    )
    db.add(audit_log)
    await db.delete(current_user)
    await db.commit()


@router.post("/me/verify-email/resend")
async def resend_verification(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email."""
    try:
        assert not current_user.is_verified, "Email already verified"

        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        current_user.verification_code = verification_code
        current_user.verification_code_expires_at = verification_expires

        audit_log = AuditLog(
            user_id=current_user.id,
            action="resend_verification",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Verification email resent",
        )
        db.add(audit_log)
        await db.commit()

        try:
            await email_service.send_verification_email(
                to_email=current_user.email,
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            audit_log = AuditLog(
                user_id=current_user.id,
                action="send_verification_email",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Failed to send verification email: {str(e)}",
            )
            db.add(audit_log)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to send verification email",
            )

        return {"message": "Verification email sent"}

    except AssertionError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )


@router.post("/verify-email/resend")
async def resend_verification_public(
    request: Request,
    email_in: EmailRequest,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email (public endpoint)."""
    stmt = select(User).where(
        User.email == email_in.email.lower(),
        User.is_verified.is_(False),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS
        )

        user.verification_code = verification_code
        user.verification_code_expires_at = verification_expires

        audit_log = AuditLog(
            user_id=user.id,
            action="resend_verification_public",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Verification email resent",
        )
        db.add(audit_log)
        await db.commit()

        try:
            await email_service.send_verification_email(
                to_email=user.email,
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            audit_log = AuditLog(
                user_id=user.id,
                action="send_verification_email",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Failed to send verification email: {str(e)}",
            )
            db.add(audit_log)
            await db.commit()

    return {
        "message": "If the email exists and is unverified, "
        "a new verification email has been sent"
    }


@router.post("/me/email", response_model=dict[str, str])
async def request_email_change(
    request: Request,
    email_in: EmailRequest,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Request email address change."""
    new_email = email_in.email.lower()
    if new_email == current_user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New email must be different from current email",
        )

    stmt = select(User).where(User.email == new_email)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(
        seconds=settings.VERIFICATION_CODE_TTL_SECS
    )

    current_user.verification_code = verification_code
    current_user.verification_code_expires_at = verification_expires
    current_user.pending_email = new_email

    audit_log = AuditLog(
        user_id=current_user.id,
        action="request_email_change",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Requested email change to {new_email}",
    )
    db.add(audit_log)
    await db.commit()

    try:
        await email_service.send_verification_email(
            to_email=new_email,
            verification_code=verification_code,
        )
    except EmailError as e:
        logger.error("Email change request failed: %s", e.detail)
        audit_log = AuditLog(
            user_id=current_user.id,
            action="send_verification_email",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Failed to send verification email: {e.detail}",
        )
        db.add(audit_log)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to send verification email. Please try again later.",
        )

    return {"message": "Verification email sent to new address"}


@router.post("/me/email/verify", response_model=UserResponse)
async def verify_email_change(
    request: Request,
    code: str,
    current_user: CurrentUser,
    db: DBSession,
) -> User:
    """Verify and complete email address change."""
    if not current_user.pending_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending email change",
        )
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

    stmt = select(User).where(
        User.email == current_user.pending_email,
        User.id != current_user.id,
    )
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already taken",
        )

    old_email = current_user.email

    current_user.email = current_user.pending_email
    current_user.pending_email = None
    current_user.verification_code = None
    current_user.verification_code_expires_at = None
    current_user.is_verified = True

    audit_log = AuditLog(
        user_id=current_user.id,
        action="verify_email_change",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Changed email from {old_email} to {current_user.email}",
    )
    db.add(audit_log)
    await db.commit()
    await db.refresh(current_user)

    try:
        await email_service.send_email_change_notification(
            to_email=old_email,
            new_email=current_user.email,
        )
    except Exception as e:
        logger.error("Failed to send change notification: %s", str(e))
        audit_log = AuditLog(
            user_id=current_user.id,
            action="send_email_change_notification",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Failed to send change notification: {str(e)}",
        )
        db.add(audit_log)
        await db.commit()

    return current_user
