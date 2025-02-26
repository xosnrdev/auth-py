"""Authentication endpoints for login, logout, token management, and password reset."""

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
    _: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: DBSession,
) -> TokenResponse:
    """Authenticate user with email/password following OAuth2 password grant."""
    stmt = select(User).where(User.email == form_data.username.lower())
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

    tokens = await token_service.create_tokens(
        user_id=user.id,
        user_agent=request.headers.get("user-agent", ""),
        ip_address=get_client_ip(request),
        response=None,
    )

    audit_log = AuditLog(
        user_id=user.id,
        action="login",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details="Successful login",
    )
    db.add(audit_log)
    await db.commit()

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
    """Refresh access token using refresh token following OAuth2 refresh grant."""
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
        token_data = await token_service.verify_token(token, TokenType.REFRESH)

        stmt = select(User).where(User.id == token_data.sub)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if not user or not user.is_active:
            await token_service.revoke_token(token)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
                headers={"WWW-Authenticate": "Bearer"},
            )

        is_api_client = "application/json" in request.headers.get("content-type", "")
        tokens = await token_service.create_tokens(
            user_id=user.id,
            user_agent=request.headers.get("user-agent", ""),
            ip_address=get_client_ip(request),
            response=None if is_api_client else response
        )

        await token_service.revoke_token(token)

        audit_log = AuditLog(
            user_id=user.id,
            action="refresh_token",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Refreshed access token",
        )
        db.add(audit_log)
        await db.commit()

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
                refresh_token=None,
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
    _: Token,
    db: DBSession,
) -> None:
    """Logout user and revoke current session following RFC 7009."""
    try:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            access_token = auth_header[7:]
            await token_service.revoke_token(access_token)

        await token_service.revoke_all_user_tokens(current_user.id.hex)

        audit_log = AuditLog(
            user_id=current_user.id,
            action="logout",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Logged out",
        )
        db.add(audit_log)
        await db.commit()

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
    """Logout from all devices and revoke all user sessions."""
    try:
        await token_service.revoke_all_user_tokens(current_user.id.hex)

        audit_log = AuditLog(
            user_id=current_user.id,
            action="logout_all",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details="Logged out from all devices",
        )
        db.add(audit_log)
        await db.commit()

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
    db: DBSession,
) -> dict[str, str]:
    """Request a password reset"""
    stmt = select(User).where(User.email == reset_request.email.lower())
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        return {"message": "If the account exists, a password reset email has been sent"}

    if not user.is_active:
        return {"message": "If the account exists, a password reset email has been sent"}

    reset_token = token_hex(settings.VERIFICATION_CODE_LENGTH)
    reset_expires = datetime.now(UTC) + timedelta(seconds=settings.VERIFICATION_CODE_EXPIRES_SECS)

    user.reset_token = reset_token
    user.reset_token_expires_at = reset_expires

    try:
        await email_service.send_password_reset_email(
            to_email=user.email,
            reset_token=reset_token,
        )
    except Exception as e:
        logger.error("Failed to send password reset email: %s", str(e))
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
    """Verify password reset token and set new password."""
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

    user.password_hash = get_password_hash(reset_verify.password)
    user.reset_token = None
    user.reset_token_expires_at = None

    await token_service.revoke_all_user_tokens(user.id.hex)

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
