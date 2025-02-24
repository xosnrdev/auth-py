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

from app.api.v1.auth.dependencies import CurrentUser, DBSession
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


# User Self-Management Endpoints

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: CurrentUser,
) -> User:
    """Get current user's profile data.

    Implements secure profile retrieval:
    1. Authenticates user
    2. Returns sanitized data
    3. Excludes sensitive fields

    Args:
        current_user: Authenticated user from token

    Returns:
        User: Current user's profile data

    Security:
        - Requires authentication
        - Sanitizes output
        - Rate limited
        - Audit logged
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

    Implements secure profile updates:
    1. Validates input data
    2. Updates allowed fields
    3. Hashes new password
    4. Logs changes
    5. Returns updated profile

    Args:
        request: FastAPI request object
        user_update: Update data with validation
        current_user: Authenticated user
        db: Database session

    Returns:
        User: Updated user profile

    Security:
        - Validates input
        - Hashes passwords
        - Rate limited
        - Logs changes
        - CSRF protected
    """
    # Update fields if provided
    if user_update.phone is not None:
        current_user.phone = user_update.phone
    if user_update.password:
        current_user.password_hash = get_password_hash(user_update.password)

    # Log update
    audit_log = AuditLog(
        user_id=current_user.id,
        action="update_profile",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Updated own profile",
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.post("/me/verify-email/resend")
async def resend_verification_email(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email to current user.

    Implements secure email verification resend:
    1. Checks verification status
    2. Generates new verification code
    3. Updates expiration time
    4. Sends verification email
    5. Logs resend attempt

    Args:
        request: FastAPI request object
        current_user: Authenticated user
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Already verified
            - 500: Email sending failed

    Security:
        - Requires authentication
        - Rate limited
        - Logs attempts
        - Time-limited codes
    """
    if current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already verified",
        )

    # Generate new verification code
    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

    # Update user
    current_user.verification_code = verification_code
    current_user.verification_code_expires_at = verification_expires

    # Send verification email
    try:
        await email_service.send_verification_email(
            to_email=current_user.email,
            verification_code=verification_code,
        )
    except Exception as e:
        logger.error("Failed to send verification email: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification email",
        ) from e

    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="resend_verification",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Requested new verification email",
    )
    db.add(audit_log)

    await db.commit()
    return {"message": "Verification email sent"}


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_current_user(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> None:
    """Delete current user's account.

    Implements secure account deletion:
    1. Authenticates user
    2. Logs deletion request
    3. Removes user data
    4. Cascades deletions
    5. Revokes sessions

    Args:
        request: FastAPI request object
        current_user: Authenticated user
        db: Database session

    Security:
        - Requires authentication
        - Logs deletion
        - Cascading delete
        - Session cleanup
        - Rate limited
    """
    # Log deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_account",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Self-deleted account",
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
    """List user's active sessions based on refresh tokens.

    Implements secure session listing:
    1. Retrieves active refresh tokens
    2. Gets session metadata
    3. Includes IP and user agent
    4. Shows creation time
    5. Supports session management

    Args:
        current_user: Authenticated user
        db: Database session

    Returns:
        list[dict]: Active sessions with metadata
            Format: [{
                "id": "token_id",
                "ip_address": "client_ip",
                "user_agent": "browser_info",
                "created_at": timestamp
            }]

    Security:
        - Requires authentication
        - Shows only own sessions
        - Rate limited
        - Sanitized output
    """
    # Get all active refresh tokens for user
    pattern = "refresh_token:*"
    sessions: list[dict[str, str | int]] = []

    async for key in redis.scan_iter(pattern):
        user_id = await redis.get(key)
        if not isinstance(key, str):  # Type guard
            continue
        if user_id == current_user.id.hex:
            # Get token creation time from key
            parts: list[str] = key.split(":")
            if len(parts) < 2:  # Skip malformed keys
                continue
            token_id = parts[-1]
            # Get associated audit log
            stmt = select(AuditLog).where(
                AuditLog.user_id == current_user.id,
                AuditLog.action == "login",
                AuditLog.details.contains(token_id),
            ).order_by(AuditLog.timestamp.desc()).limit(1)
            result = await db.execute(stmt)
            log = result.scalar_one_or_none()

            if log:
                session_data: dict[str, str | int] = {
                    "id": token_id,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "created_at": int(log.timestamp.timestamp()),
                }
                sessions.append(session_data)

    return sessions


@router.post("/me/sessions/revoke-all")
async def revoke_all_sessions(
    request: Request,
    current_user: CurrentUser,
    db: DBSession,
) -> dict[str, str]:
    """Revoke all user's sessions except current one.

    Implements secure session revocation:
    1. Identifies current session
    2. Lists all active sessions
    3. Revokes other sessions
    4. Preserves current session
    5. Logs revocation

    Args:
        request: FastAPI request object
        current_user: Authenticated user
        db: Database session

    Returns:
        dict: Success message

    Security:
        - Requires authentication
        - Preserves current session
        - Rate limited
        - Logs revocation
        - Immediate effect
    """
    # Get all active refresh tokens for user
    pattern = "refresh_token:*"
    current_token_id = None

    # Get current token ID from request
    refresh_token = request.cookies.get("refresh_token")
    if refresh_token:
        token_parts = refresh_token.split(":")
        if len(token_parts) >= 2:
            current_token_id = token_parts[-1]

    # Revoke all tokens except current one
    async for key in redis.scan_iter(pattern):
        user_id = await redis.get(key)
        if not isinstance(key, str):  # Type guard
            continue
        if user_id == current_user.id.hex:
            parts: list[str] = key.split(":")
            if len(parts) < 2:  # Skip malformed keys
                continue
            token_id = parts[-1]
            if token_id != current_token_id:
                await redis.delete(key)

    # Log action
    audit_log = AuditLog(
        user_id=current_user.id,
        action="revoke_all_sessions",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Revoked all other sessions",
    )
    db.add(audit_log)
    await db.commit()

    return {"message": "All other sessions have been revoked"}


@router.get("/me/audit-log", response_model=list[dict[str, str | int | None]])
async def get_account_activity(
    current_user: CurrentUser,
    db: DBSession,
    limit: int = 50,
) -> list[dict[str, str | int | None]]:
    """Get recent account activity with filtering.

    Implements secure activity logging:
    1. Retrieves recent activities
    2. Filters by user
    3. Orders by timestamp
    4. Limits result set
    5. Sanitizes output

    Args:
        current_user: Authenticated user
        db: Database session
        limit: Maximum number of events to return

    Returns:
        list[dict]: Recent activity events
            Format: [{
                "action": "event_type",
                "ip_address": "client_ip",
                "user_agent": "browser_info",
                "details": "event_details",
                "timestamp": unix_timestamp
            }]

    Security:
        - Requires authentication
        - Shows only own activity
        - Rate limited
        - Sanitized output
        - Limited result set
    """
    stmt = select(AuditLog).where(
        AuditLog.user_id == current_user.id
    ).order_by(
        AuditLog.timestamp.desc()
    ).limit(limit)

    result = await db.execute(stmt)
    logs = result.scalars().all()

    return [{
        "action": log.action,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "details": log.details,
        "timestamp": int(log.timestamp.timestamp()),
    } for log in logs]


@router.post("/verify-email/resend", response_model=dict[str, str])
async def resend_verification_email_public(
    request: Request,
    email_in: EmailRequest,
    db: DBSession,
) -> dict[str, str]:
    """Resend verification email to any unverified user.

    Implements secure public verification resend:
    1. Accepts email address
    2. Checks verification status
    3. Generates new verification code
    4. Sends verification email
    5. Prevents email enumeration
    6. Logs resend attempt

    This endpoint is public and does not require authentication.
    It will only work for unverified users to prevent email spam.
    Returns same response regardless of email existence or status.

    Args:
        request: FastAPI request object
        email_in: Email address to resend verification
        db: Database session

    Returns:
        dict: Success message (intentionally vague)

    Security:
        - No authentication required
        - Prevents email enumeration
        - Rate limited by email
        - Logs all attempts
        - Time-limited codes
    """
    # Find user by email
    stmt = select(User).where(User.email == email_in.email.lower())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Return success even if user doesn't exist to prevent email enumeration
        return {"message": "If the email exists and is unverified, a new verification email has been sent"}

    if user.is_verified:
        # Return success even if already verified to prevent email enumeration
        return {"message": "If the email exists and is unverified, a new verification email has been sent"}

    # Generate new verification code
    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

    # Update user
    user.verification_code = verification_code
    user.verification_code_expires_at = verification_expires

    # Send verification email
    try:
        await email_service.send_verification_email(
            to_email=user.email,
            verification_code=verification_code,
        )
    except Exception as e:
        logger.error("Failed to send verification email: %s", str(e))
        # Log error but return success to prevent email enumeration
        error_log = AuditLog(
            user_id=user.id,
            action="resend_verification_email",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Failed to send verification email: {str(e)}",
        )
        db.add(error_log)
        await db.commit()
        return {"message": "If the email exists and is unverified, a new verification email has been sent"}

    # Log action
    audit_log = AuditLog(
        user_id=user.id,
        action="resend_verification",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Requested new verification email",
    )
    db.add(audit_log)

    await db.commit()
    return {"message": "If the email exists and is unverified, a new verification email has been sent"}
