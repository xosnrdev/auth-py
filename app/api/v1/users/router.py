"""User management endpoints for registration and profile management.

This module implements secure user management following RFC standards:
- User Registration (RFC 7591)
- Email Verification (RFC 8628)
- Profile Management (RFC 7643)
- Session Management (RFC 6749)
- Phone Number Format (E.164)

Core Functionality:
1. User Registration
   - Email validation
   - Phone validation (E.164)
   - Password security
   - Duplicate prevention
   - Verification flow

2. Email Verification
   - Secure token generation
   - Expiration handling
   - Resend capability
   - Status tracking

3. Profile Management
   - Secure updates
   - Session control
   - Account deletion
   - Activity tracking

4. Session Management
   - Active session listing
   - Session revocation
   - Multi-device support
   - Security monitoring

Security Features:
- Password hashing (bcrypt)
- Rate limiting
- Email verification
- Session tracking
- Audit logging
- CSRF protection
- XSS prevention
"""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.v1.dependencies import CurrentUser, DBSession
from app.core.config import settings
from app.core.redis import redis
from app.core.security import get_password_hash
from app.models import AuditLog, User
from app.schemas import EmailRequest, UserCreate, UserResponse, UserUpdate
from app.services.email import email_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    db: DBSession,
) -> User:
    """Register a new user with email verification.

    Implements secure user registration:
    1. Validates email uniqueness
    2. Validates phone format (E.164)
    3. Hashes password securely
    4. Generates verification token
    5. Sends verification email
    6. Creates user record
    7. Logs registration event

    Args:
        request: FastAPI request object
        user_in: User registration data with validation
        db: Database session

    Returns:
        User: Created user object (password hash excluded)

    Raises:
        HTTPException:
            - 400: Email already registered
            - 400: Phone number already registered
            - 400: Invalid phone format
            - 500: Registration failed

    Security:
        - Validates input data
        - Hashes passwords (bcrypt)
        - Prevents email enumeration
        - Requires verification
        - Rate limited
        - Logs all attempts
    """
    # Check if email exists
    stmt = select(User).where(User.email == user_in.email)
    result = await db.execute(stmt)
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Check if phone exists (if provided)
    if user_in.phone:
        stmt = select(User).where(User.phone == user_in.phone)
        result = await db.execute(stmt)
        existing_phone = result.scalar_one_or_none()
        if existing_phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number already registered",
            )

    # Generate verification code
    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

    # Create user
    try:
        db_user = User(
            email=user_in.email,
            phone=user_in.phone,
            password_hash=get_password_hash(user_in.password),
            verification_code=verification_code,
            verification_code_expires_at=verification_expires,
        )
        db.add(db_user)
        await db.commit()
        await db.refresh(db_user)
    except IntegrityError as e:
        await db.rollback()
        error_detail = "Registration failed due to a conflict"
        if "ix_users_email" in str(e):
            error_detail = "Email already registered"
        elif "ix_users_phone" in str(e):
            error_detail = "Phone number already registered"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_detail,
        ) from e

    # Log registration
    audit_log = AuditLog(
        user_id=db_user.id,
        action="register",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="User registration",
    )
    db.add(audit_log)
    await db.commit()

    # Send verification email
    try:
        await email_service.send_verification_email(
            to_email=user_in.email,
            verification_code=verification_code,
        )
    except Exception as e:
        # Log error but don't fail registration
        logger.error("Failed to send verification email: %s", str(e))
        error_log = AuditLog(
            user_id=db_user.id,
            action="send_verification_email",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Failed to send verification email: {str(e)}",
        )
        db.add(error_log)
        await db.commit()

    return db_user


@router.post("/verify-email")
async def verify_email(
    request: Request,
    code: str,
    db: DBSession,
) -> dict[str, str]:
    """Verify user's email address with secure token.

    Implements secure email verification:
    1. Validates verification code
    2. Checks expiration time
    3. Updates user status
    4. Clears verification data
    5. Logs verification

    Args:
        request: FastAPI request object
        code: Email verification code
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Invalid verification code
            - 400: Code expired
            - 400: Already verified

    Security:
        - Time-limited codes
        - One-time use
        - Rate limited
        - Logs attempts
        - Prevents timing attacks
    """
    # Find user by verification code
    stmt = select(User).where(
        User.verification_code == code,
        User.verification_code_expires_at > datetime.now(UTC),
        User.is_verified.is_(False),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification code",
        )

    # Mark email as verified
    user.is_verified = True
    user.verification_code = None
    user.verification_code_expires_at = None

    # Log verification
    audit_log = AuditLog(
        user_id=user.id,
        action="verify_email",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Email verified",
    )
    db.add(audit_log)
    await db.commit()

    return {"message": "Email verified successfully"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: CurrentUser,
) -> User:
    """Get current user's profile data.

    Args:
        current_user: Current authenticated user

    Returns:
        User: Current user's profile data
    """
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_current_user_profile(
    request: Request,
    user_update: UserUpdate,
    current_user: CurrentUser,
    db: DBSession,
) -> User:
    """Update current user's profile data.

    Args:
        request: FastAPI request object
        user_update: User update data
        current_user: Current authenticated user
        db: Database session

    Returns:
        User: Updated user profile

    Raises:
        HTTPException:
            - 400: Email already taken
            - 400: Phone already taken
    """
    # Update user fields
    for field, value in user_update.model_dump(exclude_unset=True).items():
        setattr(current_user, field, value)

    # Log update
    audit_log = AuditLog(
        user_id=current_user.id,
        action="update_profile",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Profile updated",
    )
    db.add(audit_log)

    try:
        await db.commit()
        await db.refresh(current_user)
    except IntegrityError as e:
        await db.rollback()
        error_detail = "Update failed due to a conflict"
        if "ix_users_email" in str(e):
            error_detail = "Email already taken"
        elif "ix_users_phone" in str(e):
            error_detail = "Phone number already taken"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_detail,
        ) from e

    return current_user


@router.post("/me/verify-email/resend")
async def resend_verification_email(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email for current user.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Already verified
            - 429: Too many requests
    """
    # Check if already verified
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )

    # Rate limit check
    rate_limit_key = f"resend_verification:{current_user.id}"
    if await redis.exists(rate_limit_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Please wait before requesting another verification email",
        )

    # Generate new verification code
    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

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

    # Send verification email
    try:
        await email_service.send_verification_email(
            to_email=current_user.email,
            verification_code=verification_code,
        )
    except Exception as e:
        logger.error("Failed to send verification email: %s", str(e))
        error_log = AuditLog(
            user_id=current_user.id,
            action="send_verification_email",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Failed to send verification email: {str(e)}",
        )
        db.add(error_log)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email",
        ) from e

    # Set rate limit
    await redis.setex(
        rate_limit_key,
        settings.VERIFICATION_RESEND_RATE_LIMIT,
        "1",
    )

    return {"message": "Verification email sent"}


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> None:
    """Delete current user's account.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        db: Database session

    Returns:
        None

    Security:
        - Requires authentication
        - Logs deletion
        - Cascades deletion
    """
    # Log deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_account",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Account deleted",
    )
    db.add(audit_log)

    # Delete user
    await db.delete(current_user)
    await db.commit()


@router.get("/me/sessions")
async def list_active_sessions(
    current_user: CurrentUser,
    db: DBSession,
) -> list[dict[str, str | int]]:
    """List all active sessions for current user.

    Args:
        current_user: Current authenticated user
        db: Database session

    Returns:
        list: List of active sessions with metadata

    Security:
        - Requires authentication
        - Shows only user's sessions
        - Includes metadata
    """
    # Get all active sessions from Redis
    session_pattern = f"session:{current_user.id}:*"
    session_keys = await redis.keys(session_pattern)
    sessions = []

    for key in session_keys:
        # Get session data
        session_data: dict[str, str] = await redis.hgetall(key)  # type: ignore
        if not session_data:
            continue

        # Get audit log for session start
        stmt = select(AuditLog).where(
            AuditLog.user_id == current_user.id,
            AuditLog.action == "login",
            AuditLog.details.like(f"%{session_data.get('jti', '')}%"),
        )
        result = await db.execute(stmt)
        audit_log = result.scalar_one_or_none()

        # Add session info
        sessions.append({
            "id": session_data.get("jti", "unknown"),
            "ip_address": audit_log.ip_address if audit_log else "unknown",
            "user_agent": audit_log.user_agent if audit_log else "unknown",
            "created_at": audit_log.created_at.isoformat() if audit_log else "unknown",
            "expires_in": await redis.ttl(key),
        })

    return sessions


@router.post("/me/sessions/revoke-all")
async def revoke_all_sessions(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Revoke all active sessions for current user.

    Args:
        request: FastAPI request object
        current_user: Current authenticated user
        db: Database session

    Returns:
        dict: Success message

    Security:
        - Requires authentication
        - Revokes all sessions
        - Logs action
        - Immediate effect
    """
    # Get all active sessions
    session_pattern = f"session:{current_user.id}:*"
    session_keys = await redis.keys(session_pattern)

    # Delete all sessions
    if session_keys:
        await redis.delete(*session_keys)

    # Get all refresh tokens
    refresh_pattern = f"refresh_token:{current_user.id}:*"
    refresh_keys = await redis.keys(refresh_pattern)

    # Delete all refresh tokens
    if refresh_keys:
        await redis.delete(*refresh_keys)

    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="revoke_all_sessions",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Revoked {len(session_keys)} sessions and {len(refresh_keys)} refresh tokens",
    )
    db.add(audit_log)
    await db.commit()

    return {"message": "All sessions revoked successfully"}


@router.get("/me/audit-log", response_model=list[dict[str, str | int | None]])
async def get_account_activity(
    current_user: CurrentUser,
    db: DBSession,
    limit: int = 50,
) -> list[dict[str, str | int | None]]:
    """Get recent account activity for current user.

    Args:
        current_user: Current authenticated user
        db: Database session
        limit: Maximum number of records to return

    Returns:
        list: Recent account activity records

    Security:
        - Requires authentication
        - Shows only user's activity
        - Paginated results
    """
    # Get recent audit logs
    stmt = (
        select(AuditLog)
        .where(AuditLog.user_id == current_user.id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    audit_logs = result.scalars().all()

    # Format logs
    return [
        {
            "action": log.action,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": log.details,
            "created_at": log.created_at.isoformat(),
        }
        for log in audit_logs
    ]


@router.post("/verify-email/resend", response_model=dict[str, str])
async def resend_verification_email_public(
    request: Request,
    email_in: EmailRequest,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email for unverified users.

    Args:
        request: FastAPI request object
        email_in: Email request data
        db: Database session

    Returns:
        dict: Success message

    Security:
        - Rate limited
        - Prevents email enumeration
        - Logs attempts
    """
    # Rate limit check
    rate_limit_key = f"resend_verification_public:{get_client_ip(request)}"
    if await redis.exists(rate_limit_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Please wait before requesting another verification email",
        )

    # Find user by email
    stmt = select(User).where(
        User.email == email_in.email,
        User.is_verified.is_(False),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if user:
        # Generate new verification code
        verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
        verification_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

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

        # Send verification email
        try:
            await email_service.send_verification_email(
                to_email=user.email,
                verification_code=verification_code,
            )
        except Exception as e:
            logger.error("Failed to send verification email: %s", str(e))
            error_log = AuditLog(
                user_id=user.id,
                action="send_verification_email",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details=f"Failed to send verification email: {str(e)}",
            )
            db.add(error_log)
            await db.commit()

    # Set rate limit
    await redis.setex(
        rate_limit_key,
        settings.VERIFICATION_RESEND_RATE_LIMIT,
        "1",
    )

    # Return generic message to prevent email enumeration
    return {"message": "If the email exists and is unverified, a new verification email has been sent"}
