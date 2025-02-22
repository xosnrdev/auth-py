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
from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    OAuth2PasswordRequestForm,
)
from sqlalchemy import select

from app.api.v1.auth.dependencies import CurrentUser, DBSession
from app.core import email_service
from app.core.config import settings
from app.core.jwt import TokenResponse, token_service
from app.core.security import get_password_hash, verify_password
from app.models import AuditLog, User
from app.schemas import (
    TokenIntrospectionResponse,
    TokenMetadataResponse,
    UserCreate,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

bearer_scheme = HTTPBearer()


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


@router.post("/login", response_model=UserResponse | TokenResponse)
async def login(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> UserResponse | TokenResponse:
    """Login user and create tokens.

    For web clients (browser), sets refresh token in HTTP-only cookie
    and returns user data.

    For API clients (mobile/desktop), returns both access and refresh tokens
    in JSON response.

    Args:
        request: FastAPI request object
        response: FastAPI response object
        form_data: OAuth2 password request form
        db: Database session

    Returns:
        UserResponse | TokenResponse: User data for web clients, tokens for API clients

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

    # Detect client type from Accept header
    wants_json = "application/json" in request.headers.get("accept", "")

    # Create tokens based on client type
    tokens = await token_service.create_tokens(
        user_id=user.id,
        response=None if wants_json else response,
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

    # Return tokens for API clients, user data for web clients
    if wants_json and tokens:
        return tokens
    return UserResponse.model_validate(user)


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
    refresh_token: str | None = Cookie(None, alias=settings.COOKIE_NAME),
) -> dict[str, str]:
    """Logout user by revoking refresh token.

    For web clients, also clears the refresh token cookie.
    For API clients, expects the refresh token to be passed in request body.

    Args:
        response: FastAPI response object
        refresh_token: Refresh token from cookie or request body

    Returns:
        dict: Success message
    """
    if refresh_token:
        # Revoke refresh token
        try:
            await token_service.revoke_token(refresh_token)
        except Exception as e:
            logger.warning("Failed to revoke token: %s", str(e))

        # Clear cookie for web clients
        response.delete_cookie(
            key=settings.COOKIE_NAME,
            httponly=settings.COOKIE_HTTPONLY,
            secure=settings.COOKIE_SECURE,
            samesite=settings.COOKIE_SAMESITE,
        )

    return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    refresh_token: str | None = Cookie(None, alias=settings.COOKIE_NAME),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> TokenResponse:
    """Refresh access token using refresh token.

    For web clients, gets refresh token from cookie.
    For API clients, expects refresh token in Authorization header.

    Args:
        request: FastAPI request object
        response: FastAPI response object
        refresh_token: Refresh token from cookie
        credentials: Bearer token from Authorization header

    Returns:
        TokenResponse: New access and refresh tokens

    Raises:
        HTTPException:
            - 401: Invalid or expired refresh token
            - 401: Token has been revoked
    """
    # Get refresh token from either cookie or header
    token = refresh_token or (credentials.credentials if credentials else None)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
        )

    try:
        # Verify refresh token
        token_data = await token_service.verify_token(token, "refresh")
        user_id = UUID(token_data.sub)

        # Create new tokens
        wants_json = "application/json" in request.headers.get("accept", "")
        tokens = await token_service.create_tokens(
            user_id=user_id,
            response=None if wants_json else response,
        )

        # Revoke old refresh token
        await token_service.revoke_token(token)

        # Return new tokens
        if tokens:
            return tokens
        return TokenResponse(
            access_token="",  # Cookie-based flow, no tokens in response
            refresh_token="",
            token_type="bearer",
            expires_in=0,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.post("/introspect", response_model=TokenIntrospectionResponse)
async def introspect_token(
    token: str,
    current_user: CurrentUser,  # Already includes Depends
    token_type_hint: Literal["access", "refresh"] | None = None,
) -> TokenIntrospectionResponse:
    """Introspect a token following RFC 7662.

    This endpoint allows resource servers to validate tokens
    and get information about the token, its scope, and the user.

    Args:
        token: Token to introspect
        current_user: Current authenticated user (from dependency)
        token_type_hint: Optional hint about token type

    Returns:
        TokenIntrospectionResponse: Token introspection data

    Raises:
        HTTPException:
            - 401: Not authenticated
            - 400: Invalid token
    """
    try:
        # Try to verify token
        token_data = await token_service.verify_token(
            token,
            token_type_hint or "access",  # Default to access token
        )

        # Convert datetime to timestamps
        exp = int(token_data.exp.timestamp()) if token_data.exp else None
        iat = int(token_data.iat.timestamp()) if token_data.iat else None

        # Include username if token subject matches authenticated user
        username = current_user.email if token_data.sub == str(current_user.id) else None

        return TokenIntrospectionResponse(
            active=True,
            token_type=token_data.type,
            username=username,
            exp=exp,
            iat=iat,
            nbf=iat,  # Token is valid from issuance
            sub=token_data.sub,
            jti=token_data.jti,
            iss=settings.APP_URL,
            aud=[settings.APP_URL],  # List of intended audiences
        )

    except Exception:
        # RFC 7662: Don't leak token validation errors
        return TokenIntrospectionResponse(active=False)


@router.get("/.well-known/oauth-authorization-server", response_model=TokenMetadataResponse)
async def get_token_metadata() -> TokenMetadataResponse:
    """Get token endpoint metadata following OAuth 2.0 Authorization Server Metadata.

    This endpoint provides OAuth 2.0 clients with metadata about the
    authorization server's configuration, including supported features
    and endpoints.

    Returns:
        TokenMetadataResponse: Authorization server metadata
    """
    return TokenMetadataResponse(
        issuer=settings.APP_URL,
        authorization_endpoint=f"{settings.APP_URL}/api/v1/auth/social/{{provider}}/authorize",
        token_endpoint=f"{settings.APP_URL}/api/v1/auth/login",
        response_types_supported=["code"],
        grant_types_supported=["authorization_code", "refresh_token", "password"],
        token_endpoint_auth_methods_supported=["client_secret_post"],
        code_challenge_methods_supported=["S256"],
    )
