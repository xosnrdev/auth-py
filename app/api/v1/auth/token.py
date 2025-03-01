"""Authentication endpoints for login, logout, token management, and password reset."""

import logging
from datetime import UTC, datetime, timedelta
from secrets import token_hex
from typing import Annotated, cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError

from app.api.v1.dependencies import (
    AuditRepo,
    CurrentUser,
    Token,
    UserRepo,
)
from app.core.config import settings
from app.core.errors import NotFoundError
from app.core.security import get_password_hash, verify_password
from app.schemas import PasswordResetRequest, PasswordResetVerify
from app.services.email import email_service
from app.services.token import TokenResponse, TokenType, token_service
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> TokenResponse:
    """Authenticate user with email/password following OAuth2 password grant.

    Args:
        request: FastAPI request
        form_data: OAuth2 password form data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Token response with access and refresh tokens

    Raises:
        HTTPException: If authentication fails
    """
    try:
        # Get user by email
        user = await user_repo.get_by_email(form_data.username.lower())

        # Verify password
        if not verify_password(form_data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Check user status
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

        # Create tokens
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
            response=None,
        )

        # Log successful login
        await audit_repo.create({
            "user_id": user.id,
            "action": "login",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Successful login",
        })

        return TokenResponse(
            access_token=cast(dict[str, str], tokens)["access_token"],
            refresh_token=cast(dict[str, str], tokens)["refresh_token"],
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
        )

    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.error("Login failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> TokenResponse:
    """Refresh access token using refresh token following OAuth2 refresh grant.

    Args:
        request: FastAPI request
        response: FastAPI response
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Token response with new access and refresh tokens

    Raises:
        HTTPException: If token refresh fails
    """
    # Get refresh token from request
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

        try:
            # Get user by ID
            user = await user_repo.get_by_id(UUID(token_data.sub))
            if not user.is_active:
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
                response=None if is_api_client else response
            )

            # Revoke old token
            await token_service.revoke_token(token)

            # Log token refresh
            await audit_repo.create({
                "user_id": user.id,
                "action": "refresh_token",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": "Refreshed access token",
            })

            if is_api_client:
                return TokenResponse(
                    access_token=cast(dict[str, str], tokens)["access_token"],
                    refresh_token=cast(dict[str, str], tokens)["refresh_token"],
                    token_type="bearer",
                    expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                )
            else:
                return TokenResponse(
                    access_token=cast(dict[str, str], tokens)["access_token"],
                    refresh_token=None,
                    token_type="bearer",
                    expires_in=settings.JWT_ACCESS_TOKEN_TTL_SECS,
                )

        except NotFoundError:
            await token_service.revoke_token(token)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
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
    _: Token,
    audit_repo: AuditRepo,
) -> None:
    """Logout user and revoke current session following RFC 7009.

    Args:
        request: FastAPI request
        response: FastAPI response
        current_user: Current authenticated user
        _: Access token (unused)
        audit_repo: Audit log repository

    Raises:
        HTTPException: If logout fails
    """
    try:
        # Revoke current access token
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
            await token_service.revoke_token(access_token)

        # Revoke all user tokens
        await token_service.revoke_all_user_tokens(current_user.id.hex)

        # Log logout
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "logout",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Logged out",
        })

        # Clear refresh token cookie
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
    audit_repo: AuditRepo,
) -> None:
    """Logout from all devices and revoke all user sessions.

    Args:
        request: FastAPI request
        response: FastAPI response
        current_user: Current authenticated user
        audit_repo: Audit log repository

    Raises:
        HTTPException: If logout fails
    """
    try:
        # Revoke all user tokens
        await token_service.revoke_all_user_tokens(current_user.id.hex)

        # Log logout from all devices
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "logout_all",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Logged out from all devices",
        })

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
    _: Token,
    current_user: CurrentUser,
) -> dict[str, str | list[str]]:
    """Introspect current access token following RFC 7662."""
    return {
        "sub": current_user.id.hex,
        "email": current_user.email,
        "roles": current_user.roles,
    }


@router.post("/password-reset/request")
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Request a password reset.

    Args:
        request: FastAPI request
        reset_request: Password reset request data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If request fails
    """
    try:
        # Get user by email
        user = await user_repo.get_by_email(reset_request.email.lower())

        # Generate reset token
        reset_token = token_hex(32)
        reset_token_expires = datetime.now(UTC) + timedelta(
            seconds=settings.VERIFICATION_CODE_TTL_SECS,
        )

        # Update user with reset token
        await user_repo.update(user.id, {
            "reset_token": reset_token,
            "reset_token_expires_at": reset_token_expires,
        })

        # Send reset email
        reset_url = f"{settings.FRONTEND_URL}{settings.PASSWORD_RESET_URI}?token={reset_token}"
        await email_service.send_password_reset_email(user.email, reset_url)

        # Log password reset request
        await audit_repo.create({
            "user_id": user.id,
            "action": "password_reset_request",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Password reset requested",
        })

        return {"message": "Password reset email sent"}

    except NotFoundError:
        # Return success even if email not found to prevent email enumeration
        return {"message": "Password reset email sent"}

    except Exception as e:
        logger.error("Password reset request failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to process password reset request",
        )


@router.post("/password-reset/verify")
async def verify_password_reset(
    request: Request,
    reset_verify: PasswordResetVerify,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Verify password reset token and set new password.

    Args:
        request: FastAPI request
        reset_verify: Password reset verification data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If verification fails
    """
    try:
        # Get user by reset token
        user = await user_repo.get_by_reset_token(reset_verify.token)

        # Update password
        password_hash = get_password_hash(reset_verify.password)
        await user_repo.update(user.id, {
            "password_hash": password_hash,
            "reset_token": None,
            "reset_token_expires_at": None,
        })

        # Log password reset
        await audit_repo.create({
            "user_id": user.id,
            "action": "password_reset",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": "Password reset successful",
        })

        # Revoke all existing sessions
        await token_service.revoke_all_user_tokens(user.id.hex)

        return {"message": "Password reset successful"}

    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    except Exception as e:
        logger.error("Password reset verification failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to reset password",
        )
