"""Authentication endpoints for login, logout, token management, and password reset.

This module implements RFC-compliant authentication flows including:
- Email/password authentication (RFC 6749)
- Token refresh (RFC 6749 Section 6)
- Token revocation (RFC 7009)
- Password reset with secure token
"""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import Annotated, cast

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError
from sqlalchemy import select

from app.api.v1.dependencies import CurrentUser, DBSession, Token
from app.core.config import settings
from app.core.jwt import TokenResponse, TokenType, token_service
from app.core.security import get_password_hash, verify_password
from app.models import AuditLog, User
from app.schemas import PasswordResetRequest, PasswordResetVerify
from app.services.email import email_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    _: Response,  # Not used but required by FastAPI
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> TokenResponse:
    """Authenticate user with email/password following OAuth2 password grant.

    Implements OAuth2 Resource Owner Password Credentials Grant (RFC 6749 Section 4.3):
    1. Validates email/password credentials
    2. Verifies account status (active and verified)
    3. Issues access and refresh tokens
    4. Logs successful login attempt

    Args:
        request: FastAPI request object
        _: Response object (unused but required by FastAPI)
        form_data: OAuth2 password grant credentials
        db: Database session

    Returns:
        TokenResponse: Access and refresh tokens with metadata

    Raises:
        HTTPException: If credentials invalid, account inactive, or email unverified

    Security:
        - Uses secure password hashing
        - Implements account status checks
        - Returns standardized OAuth2 response
        - Rate limited by default middleware
        - Logs all attempts for audit
    """
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
        response=None,  # Don't set cookies, return tokens in body
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
    return TokenResponse(
        access_token=cast(dict[str, str], tokens)["access_token"],
        refresh_token=cast(dict[str, str], tokens)["refresh_token"],
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRES_SECS,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    db: DBSession,
) -> TokenResponse:
    """Refresh access token using refresh token following OAuth2 refresh grant.

    Implements OAuth2 Refresh Token Grant (RFC 6749 Section 6):
    1. Validates refresh token from cookie or body
    2. Verifies token and user status
    3. Issues new access and refresh tokens
    4. Revokes old refresh token
    5. Logs token refresh

    Supports dual token delivery methods:
    - Web clients: Refresh token in HTTP-only cookie, access token in body
    - API clients: Both tokens in JSON response body

    Args:
        request: FastAPI request object
        response: FastAPI response object for cookie management
        db: Database session

    Returns:
        TokenResponse: New access token (and refresh token for API clients)

    Raises:
        HTTPException: If refresh token invalid, expired, or user inactive

    Security:
        - Implements token rotation
        - Validates token authenticity
        - Supports secure cookie-based tokens
        - Revokes compromised tokens
        - Logs all refresh attempts
    """
    # Get refresh token from cookie or body
    token = None
    body_data = await request.json() if request.headers.get("content-type") == "application/json" else {}
    if isinstance(body_data, dict):
        token = body_data.get("refresh_token")
    if not token:
        token = request.cookies.get("refresh_token")
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
        is_api_client = "application/json" in request.headers.get("content-type", "")
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
            response=None if is_api_client else response,  # Cookie for web clients
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
        if is_api_client:
            return TokenResponse(
                access_token=cast(dict[str, str], tokens)["access_token"],
                refresh_token=cast(dict[str, str], tokens)["refresh_token"],
                token_type="bearer",
                expires_in=settings.JWT_ACCESS_TOKEN_EXPIRES_SECS,
            )
        else:
            return TokenResponse(
                access_token=cast(dict[str, str], tokens)["access_token"],
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
    """Logout user and revoke current session following RFC 7009.

    Implements Token Revocation (RFC 7009):
    1. Identifies current session from access token
    2. Revokes associated refresh token
    3. Clears session cookies if present
    4. Logs logout action

    Args:
        request: FastAPI request object
        response: FastAPI response object for cookie management
        current_user: Authenticated user from token
        db: Database session

    Raises:
        HTTPException: If token revocation fails

    Security:
        - Revokes refresh tokens
        - Clears secure cookies
        - Logs all logout attempts
        - Handles both web and API clients
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
    """Logout from all devices and revoke all user sessions.

    Implements comprehensive session termination:
    1. Revokes all refresh tokens for the user
    2. Clears current session cookies
    3. Logs multi-session logout
    4. Terminates all active sessions

    Args:
        request: FastAPI request object
        response: FastAPI response object for cookie management
        current_user: Authenticated user from token
        db: Database session

    Raises:
        HTTPException: If token revocation fails

    Security:
        - Complete session termination
        - Revokes all refresh tokens
        - Clears secure cookies
        - Logs multi-device logout
        - Handles both web and API clients
    """
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
    """Introspect current access token following RFC 7662.

    Implements Token Introspection (RFC 7662):
    1. Validates current access token
    2. Returns token metadata and claims
    3. Includes user identity and roles

    Args:
        _: Token dependency for validation
        current_user: Authenticated user from token

    Returns:
        dict: Token metadata including subject, email, and roles

    Security:
        - Requires valid access token
        - Returns minimal necessary claims
        - Supports role-based access control
    """
    return {
        "sub": current_user.id.hex,
        "email": current_user.email,
        "roles": current_user.roles,
    }


@router.post("/password-reset/request")
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest,
    db: DBSession,
) -> dict[str, str]:
    """Request a password reset following security best practices.

    Implements a secure password reset flow:
    1. User requests reset with their email
    2. System generates a secure random token
    3. Token is stored in database with expiration
    4. Reset link is sent to user's email
    5. Success message returned (same response whether account exists or not)

    Args:
        request: FastAPI request object
        reset_request: Password reset request containing email
        db: Database session

    Returns:
        dict: Success message (intentionally vague to prevent email enumeration)

    Security:
        - Uses secure random token generation
        - Implements token expiration
        - Prevents email enumeration through consistent responses
        - Rate limited by default middleware
        - Logs all attempts for audit
    """
    # Find user by email
    stmt = select(User).where(User.email == reset_request.email.lower())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Return success even if user doesn't exist to prevent email enumeration
        return {"message": "If the account exists, a password reset email has been sent"}

    if not user.is_active:
        # Return success even if account is inactive to prevent email enumeration
        return {"message": "If the account exists, a password reset email has been sent"}

    # Generate reset token
    reset_token = token_hex(settings.VERIFICATION_CODE_LENGTH)
    reset_expires = datetime.now(UTC) + timedelta(hours=settings.VERIFICATION_CODE_EXPIRES_HOURS)

    # Update user
    user.reset_token = reset_token
    user.reset_token_expires_at = reset_expires

    # Send reset email
    try:
        await email_service.send_password_reset_email(
            to_email=user.email,
            reset_token=reset_token,
        )
    except Exception as e:
        logger.error("Failed to send password reset email: %s", str(e))
        # Log error but return success to prevent email enumeration
        error_log = AuditLog(
            user_id=user.id,
            action="password_reset_request",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Failed to send password reset email: {str(e)}",
        )
        db.add(error_log)
        await db.commit()
        return {"message": "If the account exists, a password reset email has been sent"}

    # Log action
    audit_log = AuditLog(
        user_id=user.id,
        action="password_reset_request",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Requested password reset",
    )
    db.add(audit_log)

    await db.commit()
    return {"message": "If the account exists, a password reset email has been sent"}


@router.post("/password-reset/verify")
async def verify_password_reset(
    request: Request,
    reset_verify: PasswordResetVerify,
    db: DBSession,
) -> dict[str, str]:
    """Verify password reset token and set new password.

    Completes the password reset flow:
    1. Validates the reset token
    2. Checks token expiration
    3. Updates password if valid
    4. Revokes all existing sessions
    5. Logs the password change

    Args:
        request: FastAPI request object
        reset_verify: Reset verification containing token and new password
        db: Database session

    Returns:
        dict: Success message

    Raises:
        HTTPException: If token is invalid or expired

    Security:
        - Validates token exists and not expired
        - Requires active user account
        - Enforces password requirements through schema validation
        - Revokes all existing sessions for security
        - Logs password change for audit
    """
    # Find user by reset token
    stmt = select(User).where(
        User.reset_token == reset_verify.token,
        User.reset_token_expires_at > datetime.now(UTC),
        User.is_active.is_(True),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Update password
    user.password_hash = get_password_hash(reset_verify.password)
    user.reset_token = None
    user.reset_token_expires_at = None

    # Revoke all refresh tokens for user
    await token_service.revoke_all_user_tokens(user.id.hex)

    # Log action
    audit_log = AuditLog(
        user_id=user.id,
        action="password_reset",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Reset password",
    )
    db.add(audit_log)

    await db.commit()
    return {"message": "Password has been reset successfully"}
