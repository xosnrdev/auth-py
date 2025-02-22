"""Authentication endpoints for login, logout, and token management."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy import select

from app.api.v1.auth.dependencies import CurrentUser, DBSession, Token
from app.core.config import settings
from app.core.jwt import TokenResponse, TokenType, token_service
from app.core.security import verify_password
from app.models import AuditLog, User
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> TokenResponse:
    """Login with username/email and password."""
    # Find user by email
    stmt = select(User).where(User.email == form_data.username.lower())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    # Verify credentials
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active and verified
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email not verified",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create tokens with metadata
    tokens = await token_service.create_tokens(
        user_id=user.id,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=get_client_ip(request),
        response=response,
    )

    # Log login
    audit_log = AuditLog(
        user_id=user.id,
        action="login",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Successful login",
    )
    db.add(audit_log)
    await db.commit()

    # Return tokens
    return tokens or TokenResponse(
        access_token=tokens.access_token if tokens else "",
        refresh_token=None,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRES_SECS,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: DBSession,
    refresh_token: str | None = None,
) -> TokenResponse:
    """Refresh access token using refresh token.

    Supports both web clients (using HTTP-only cookie) and API clients
    (using request body), following RFC 6749 Section 6.

    Cookie-based tokens (web clients):
    - Refresh token is read from HTTP-only cookie
    - New refresh token is set in HTTP-only cookie
    - Access token is returned in response body

    JSON-based tokens (API clients):
    - Refresh token is read from request body
    - Both tokens are returned in response body

    Args:
        request: FastAPI request object
        response: FastAPI response object
        db: Database session
        refresh_token: Optional refresh token in request body

    Returns:
        TokenResponse: New access token (and refresh token for API clients)

    Raises:
        HTTPException: If refresh token is invalid or missing
    """
    # Get refresh token from cookie or body
    token = refresh_token or request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token is missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Verify refresh token
        token_data = await token_service.verify_token(token, TokenType.REFRESH)

        # Get user from database
        stmt = select(User).where(User.id == token_data.sub)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            # Revoke invalid token
            await token_service.revoke_token(token)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create new tokens
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
            response=None if refresh_token else response,  # Cookie for web clients
        )

        # Revoke old token
        await token_service.revoke_token(token)

        # Log token refresh
        audit_log = AuditLog(
            user_id=user.id,
            action="refresh_token",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Refreshed access token",
        )
        db.add(audit_log)
        await db.commit()

        # Return tokens based on client type
        return tokens or TokenResponse(
            access_token=tokens.access_token if tokens else "",
            refresh_token=None,  # Web clients use cookies
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRES_SECS,
        )

    except JWTError as e:
        logger.error("Token refresh failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    current_user: CurrentUser,
    db: DBSession,
) -> None:
    """Logout and revoke tokens following RFC 7009.

    Uses the access token from Authorization header to identify and revoke
    the associated refresh token. Also clears the refresh token cookie
    for web clients.
    """
    try:
        # Revoke all refresh tokens for user
        await token_service.revoke_all_user_tokens(current_user.id.hex)

        # Log logout
        audit_log = AuditLog(
            user_id=current_user.id,
            action="logout",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Logged out",
        )
        db.add(audit_log)
        await db.commit()

        # Clear refresh token cookie for web clients
        response.delete_cookie(key="refresh_token")

    except Exception as e:
        logger.error("Logout failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/logout/all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    request: Request,
    response: Response,
    current_user: CurrentUser,
    db: DBSession,
) -> None:
    """Logout from all devices."""
    try:
        # Revoke all refresh tokens for user
        await token_service.revoke_all_user_tokens(current_user.id.hex)

        # Log logout from all devices
        audit_log = AuditLog(
            user_id=current_user.id,
            action="logout_all",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Logged out from all devices",
        )
        db.add(audit_log)
        await db.commit()

        # Clear refresh token cookie
        response.delete_cookie(key="refresh_token")

    except Exception as e:
        logger.error("Logout from all devices failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/introspect", response_model=dict[str, str | list[str]])
async def introspect_token(
    _: Token,  # Required by FastAPI for token validation
    current_user: CurrentUser,
) -> dict[str, str | list[str]]:
    """Get information about the current access token."""
    return {
        "sub": current_user.id.hex,
        "email": current_user.email,
        "roles": current_user.roles,
    }
