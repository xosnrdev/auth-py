"""Authentication router for user registration and login."""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update

from app.api.v1.auth.dependencies import CurrentUser, DBSession
from app.core.config import settings
from app.core.security import (
    create_jwt_token,
    get_password_hash,
    verify_password,
)
from app.models import AuditLog, Token, User
from app.schemas import TokenResponse, UserCreate, UserResponse

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

    Args:
        request: FastAPI request object
        user_in: User registration data
        db: Database session

    Returns:
        User: Created user

    Raises:
        HTTPException: If email already exists
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

    # Create user
    db_user = User(
        email=user_in.email,
        phone=user_in.phone,
        password_hash=get_password_hash(user_in.password),
        roles=user_in.roles,
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

    return db_user


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> TokenResponse:
    """Login with username/password.

    Args:
        request: FastAPI request object
        form_data: OAuth2 password request form
        db: Database session

    Returns:
        TokenResponse: Access and refresh tokens

    Raises:
        HTTPException: If credentials are invalid
    """
    # Get user by email
    stmt = select(User).where(User.email == form_data.username)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    # Create tokens
    access_token, access_exp = create_jwt_token(user.id, "access")
    refresh_token, refresh_exp = create_jwt_token(user.id, "refresh")

    # Store only the refresh token
    db_token = Token(
        jti=user.id,
        refresh_token=refresh_token,
        expires_at=refresh_exp,
    )
    db.add(db_token)

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

    # Return both tokens but don't expose database fields
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Convert to seconds
        refresh_token=refresh_token,
        expires_at=refresh_exp,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    user: CurrentUser,
    db: DBSession,
) -> None:
    """Logout current user.

    Args:
        request: FastAPI request object
        user: Current authenticated user
        db: Database session
    """
    # Revoke all user's refresh tokens
    stmt = (
        update(Token)
        .where(Token.jti == user.id)
        .values(revoked=True, expires_at=datetime.now(UTC))
    )
    await db.execute(stmt)

    # Log logout
    audit_log = AuditLog(
        user_id=user.id,
        action="logout",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="User logout",
    )
    db.add(audit_log)

    await db.commit()


@router.get("/me", response_model=UserResponse)
async def get_current_user(user: CurrentUser) -> User:
    """Get current user data.

    Args:
        user: Current authenticated user

    Returns:
        User: Current user data
    """
    return user
