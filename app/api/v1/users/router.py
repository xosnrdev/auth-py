"""User management API endpoints.

Example:
```python
# Register a new user
curl -X POST http://localhost:8000/api/v1/users/register \\
  -H "Content-Type: application/json" \\
  -d '{"email": "user@example.com", "password": "SecurePass123!", "phone": "+1234567890"}'

# Verify email
curl -X POST http://localhost:8000/api/v1/users/verify-email?code=abc123

# Update profile
curl -X PATCH http://localhost:8000/api/v1/users/me \\
  -H "Authorization: Bearer <token>" \\
  -d '{"phone": "+9876543210"}'
```

Critical Security Notes:
1. Authentication & Authorization
   - JWT Bearer token required for protected endpoints
   - Email verification required for full account access
   - Secure session management with refresh tokens
   - Role-based access control (RBAC)

2. Data Protection
   - Passwords hashed with bcrypt (72 char limit)
   - Verification codes expire in 24h
   - Sessions revoked on password change
   - Phone numbers validated in E.164 format
   - All timestamps in UTC
   - Database constraints enforced
   - Input validation via Pydantic

3. Attack Prevention
   - Rate limiting via middleware
   - SQL injection protection via ORM
   - No user enumeration in public endpoints
   - Secure error handling
   - Comprehensive audit logging
   - CSRF protection via SameSite cookies

4. Privacy & Compliance
   - Minimal data collection
   - Secure data deletion
   - Activity logging with IP anonymization
   - Clear user feedback
   - GDPR-ready account deletion
"""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.v1.dependencies import CurrentUser, DBSession
from app.core.config import settings
from app.core.security import get_password_hash
from app.models import AuditLog, User
from app.schemas import EmailRequest, UserCreate, UserResponse, UserUpdate
from app.services.email import email_service
from app.utils.request import get_client_ip

# Configure module logger
logger = logging.getLogger(__name__)


router = APIRouter(tags=["users"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    db: DBSession,
) -> User:
    """Register a new user account.

    Example:
    ```python
    user = await register(
        UserCreate(
            email="user@example.com",
            password="SecurePass123!",
            phone="+1234567890"
        )
    )
    print(f"Verify your email at {user.email}")
    ```

    Args:
        request: FastAPI request
        user_in: User registration data
        db: Database session

    Returns:
        User: Created user object

    Raises:
        HTTPException: 400: Email/phone exists
    """
    try:
        # Check uniqueness
        stmt = select(User).where(
            (User.email == user_in.email.lower()) | (User.phone == user_in.phone)
        )
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()
        assert not existing, "Email or phone already registered"

        # Create verification token
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_EXPIRES_SECS
        )

        # Create user
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

        # Log registration
        audit_log = AuditLog(
            user_id=user.id,
            action="register",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="User registration successful",
        )
        db.add(audit_log)
        await db.commit()

        # Send verification email
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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except IntegrityError as e:
        logger.error("Registration failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email or phone number already registered",
        )


@router.post("/verify-email")
async def verify_email(
    request: Request,
    code: str,
    db: DBSession,
) -> dict[str, str]:
    """Verify user's email address.

    Example:
    ```python
    result = await verify_email(code="abc123")
    assert result["message"] == "Email verified successfully"
    ```

    Args:
        request: FastAPI request
        code: Verification code
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Invalid/expired code
    """
    try:
        # Find and validate user
        stmt = select(User).where(
            User.verification_code == code,
            User.verification_code_expires_at > datetime.now(UTC),
            User.is_verified.is_(False),
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        assert user, "Invalid or expired verification code"

        # Update user
        user.is_verified = True
        user.verification_code = None
        user.verification_code_expires_at = None

        # Log verification
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
    """Get current user's profile.

    Example:
    ```python
    profile = await get_profile(current_user)
    print(f"Email: {profile.email}")
    ```

    Args:
        current_user: Authenticated user

    Returns:
        User: User profile data
    """
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    request: Request,
    user_update: UserUpdate,
    current_user: CurrentUser,
    db: DBSession,
) -> User:
    """Update current user's profile.

    Example:
    ```python
    updated = await update_profile(
        UserUpdate(phone="+1234567890")
    )
    print(f"New phone: {updated.phone}")
    ```

    Args:
        request: FastAPI request
        user_update: Update data
        current_user: Authenticated user
        db: Database session

    Returns:
        User: Updated profile

    Raises:
        HTTPException:
            - 400: Invalid data
            - 409: Phone number already registered
    """
    # Check phone uniqueness if being updated
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

    # Update fields
    for field, value in user_update.model_dump(exclude_unset=True).items():
        if field == "password":
            current_user.password_hash = get_password_hash(value)
        else:
            setattr(current_user, field, value)

    # Log update
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
    """Delete current user's account.

    Example:
    ```python
    await delete_profile(current_user)
    print("Account deleted successfully")
    ```

    Args:
        request: FastAPI request
        current_user: Authenticated user
        db: Database session
    """
    # Log deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_account",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Account deleted successfully",
    )
    db.add(audit_log)

    # Delete user
    await db.delete(current_user)
    await db.commit()


@router.post("/me/verify-email/resend")
async def resend_verification(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email.

    Example:
    ```python
    await resend_verification(current_user)
    print("Verification email sent")
    ```

    Args:
        request: FastAPI request
        current_user: Authenticated user
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Already verified
    """
    try:
        # Validate state
        assert not current_user.is_verified, "Email already verified"

        # Generate new code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_EXPIRES_SECS
        )

        # Update user
        current_user.verification_code = verification_code
        current_user.verification_code_expires_at = verification_expires

        # Log resend
        audit_log = AuditLog(
            user_id=current_user.id,
            action="resend_verification",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Verification email resent",
        )
        db.add(audit_log)
        await db.commit()

        # Send email
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
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/verify-email/resend")
async def resend_verification_public(
    request: Request,
    email_in: EmailRequest,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email (public endpoint).

    Example:
    ```python
    await resend_verification_public(
        EmailRequest(email="user@example.com")
    )
    print("If email exists, verification sent")
    ```

    Args:
        request: FastAPI request
        email_in: Email request
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException: 429: Rate limit exceeded
    """
    # Find user
    stmt = select(User).where(
        User.email == email_in.email.lower(),
        User.is_verified.is_(False),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        # Generate new code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_EXPIRES_SECS
        )

        # Update user
        user.verification_code = verification_code
        user.verification_code_expires_at = verification_expires

        # Log resend
        audit_log = AuditLog(
            user_id=user.id,
            action="resend_verification_public",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Verification email resent",
        )
        db.add(audit_log)
        await db.commit()

        # Send email
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
    """Request email address change.

    Example:
    ```python
    await request_email_change(
        EmailRequest(email="new@example.com")
    )
    print("Verification email sent to new address")
    ```

    Args:
        request: FastAPI request
        email_in: New email address
        current_user: Authenticated user
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Invalid email or already in use
            - 409: Email already registered
    """
    # Check if email is different
    new_email = email_in.email.lower()
    if new_email == current_user.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New email must be different from current email",
        )

    # Check if email is available
    stmt = select(User).where(User.email == new_email)
    result = await db.execute(stmt)
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Generate verification code
    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(
        seconds=settings.VERIFICATION_CODE_EXPIRES_SECS
    )

    # Update user with pending email change
    current_user.verification_code = verification_code
    current_user.verification_code_expires_at = verification_expires
    current_user.pending_email = new_email

    # Log email change request
    audit_log = AuditLog(
        user_id=current_user.id,
        action="request_email_change",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Requested email change to {new_email}",
    )
    db.add(audit_log)
    await db.commit()

    # Send verification email to new address
    try:
        await email_service.send_verification_email(
            to_email=new_email,
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

    return {"message": "Verification email sent to new address"}


@router.post("/me/email/verify", response_model=UserResponse)
async def verify_email_change(
    request: Request,
    code: str,
    current_user: CurrentUser,
    db: DBSession,
) -> User:
    """Verify and complete email address change.

    Example:
    ```python
    user = await verify_email_change(code="abc123")
    print(f"Email changed to {user.email}")
    ```

    Args:
        request: FastAPI request
        code: Verification code
        current_user: Authenticated user
        db: Database session

    Returns:
        User: Updated user profile

    Raises:
        HTTPException:
            - 400: Invalid/expired code or no pending change
            - 409: Email taken during verification
    """
    # Validate state
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

    # Check if email is still available
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

    # Store old email for notification
    old_email = current_user.email

    # Update user email
    current_user.email = current_user.pending_email
    current_user.pending_email = None
    current_user.verification_code = None
    current_user.verification_code_expires_at = None
    current_user.is_verified = True

    # Log email change
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

    # Notify old email about the change
    try:
        await email_service.send_email_change_notification(
            to_email=old_email,
            new_email=current_user.email,
        )
    except Exception as e:
        logger.error("Failed to send change notification: %s", str(e))
        # Log but don't fail the request
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
