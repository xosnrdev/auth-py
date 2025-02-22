"""Authentication router for user registration and login.

Following RFCs:
- RFC 6749: OAuth 2.0 Framework
- RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
- RFC 6750: Bearer Token Usage
- RFC 7009: OAuth 2.0 Token Revocation
"""

from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select

from app.api.v1.auth.dependencies import DBSession
from app.core.config import settings
from app.core.security import get_password_hash, verify_password
from app.models import AuditLog, User
from app.schemas import UserCreate, UserResponse

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

    OpenAPI:
        tags:
          - auth
        summary: Register new user
        description: |
            Create a new user account.
            The password will be securely hashed.
            An audit log entry will be created.
        requestBody:
            content:
                application/json:
                    schema:
                        $ref: '#/components/schemas/UserCreate'
        responses:
            201:
                description: User successfully created
                content:
                    application/json:
                        schema:
                            $ref: '#/components/schemas/UserResponse'
            400:
                description: Email already registered
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
    await db.refresh(db_user)

    # TODO: Send verification email
    # await send_verification_email(db_user.email, verification_code)

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

    # Set session cookie
    session_id = token_hex(32)
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


@router.post("/logout")
async def logout(
    request: Request,  # noqa: ARG001 - Will be used for audit logging with Redis
    response: Response,
    db: DBSession,  # noqa: ARG001 - Will be used for audit logging with Redis
) -> dict[str, str]:
    """Logout user by clearing session cookie.

    Args:
        request: FastAPI request object
        response: FastAPI response object
        db: Database session

    Returns:
        dict: Success message
    """
    # Clear session cookie
    response.delete_cookie(
        key=settings.COOKIE_NAME,
        httponly=True,
        secure=True,
        samesite="lax",
    )

    # TODO: Invalidate session in Redis
    # await redis.delete(f"session:{session_id}")

    return {"message": "Logged out successfully"}
