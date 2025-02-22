"""Authentication router for user registration and login.

Following RFCs:
- RFC 6749: OAuth 2.0 Framework
- RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
- RFC 6750: Bearer Token Usage
- RFC 7009: OAuth 2.0 Token Revocation
"""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.api.v1.auth.dependencies import DBSession
from app.core import email_service
from app.core.config import settings
from app.core.redis import delete_session, set_session
from app.core.security import get_password_hash, verify_password
from app.models import AuditLog, User
from app.schemas import UserCreate, UserResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def get_client_ip(request: Request) -> str:
    """Get client IP address from request.

    Args:
        request: FastAPI request object

    Returns:
        str: Client IP address
    """
    if request.client and request.client.host:
        return request.client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: Request,
    user_in: UserCreate,
    db: DBSession,
) -> User:
    """Register a new user.

    Creates a new user account with the provided email and password.
    The password is hashed before storage.
    An audit log entry is created for the registration.
    A verification email is sent to the user.

    Args:
        request: FastAPI request object
        user_in: User registration data
        db: Database session

    Returns:
        User: Created user object

    Raises:
        HTTPException:
            - 400: Email already registered
            - 500: Failed to send verification email
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

    # Generate verification code
    verification_code = token_hex(settings.VERIFICATION_CODE_LENGTH)
    verification_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

    # Create user
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
        # Create error audit log
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


@router.post("/login", response_model=UserResponse)
async def login(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> User:
    """Login user and set session cookie.

    Args:
        request: FastAPI request object
        response: FastAPI response object
        form_data: OAuth2 password request form
        db: Database session

    Returns:
        User: Logged in user data

    Raises:
        HTTPException:
            - 401: Invalid credentials
            - 403: Inactive user
            - 403: Email not verified
    """
    # Get user by email
    stmt = select(User).where(User.email == form_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified",
        )

    # Set session cookie and store in Redis
    session_id = token_hex(32)
    await set_session(session_id, str(user.id))
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=session_id,
        max_age=settings.COOKIE_MAX_AGE,
        httponly=settings.COOKIE_HTTPONLY,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
    )

    # Log login
    audit_log = AuditLog(
        user_id=user.id,
        action="login",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="User login",
    )
    db.add(audit_log)

    await db.commit()

    return user


@router.post("/verify-email")
async def verify_email(
    request: Request,
    code: str,
    db: DBSession,
) -> dict[str, str]:
    """Verify user's email address.

    Args:
        request: FastAPI request object
        code: Verification code sent to user's email
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException:
            - 400: Invalid or expired verification code
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


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    response: Response,
    session: str | None = Cookie(None, alias="session"),
) -> dict[str, str]:
    """Logout user by clearing session cookie.

    Args:
        response: FastAPI response object
        session: Session cookie value

    Returns:
        dict: Success message
    """
    if session:
        # Delete session from Redis
        await delete_session(session)

    # Clear session cookie
    response.delete_cookie(
        key=settings.COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="lax",
    )

    return {"message": "Logged out successfully"}
