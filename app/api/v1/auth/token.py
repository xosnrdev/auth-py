"""Authentication endpoints for login, logout, token management, and password reset."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.core.dependencies import (
    AuditRepo,
    CurrentUser,
    Token,
    UserRepo,
)
from app.core.errors import AuthError
from app.schemas import PasswordResetRequest, PasswordResetVerify
from app.services import AuthService
from app.services.token import TokenResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["auth"])


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> TokenResponse:
    """Authenticate user with email/password following OAuth2 password grant.

    Args:
        request: FastAPI request
        response: FastAPI response
        form_data: OAuth2 password form data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Token response with access and refresh tokens

    Raises:
        HTTPException: If authentication fails
    """
    try:
        auth_service = AuthService(user_repo, audit_repo)
        return await auth_service.login(request, form_data, response)
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
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
    body_data = (
        await request.json()
        if request.headers.get("content-type") == "application/json"
        else {}
    )
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
        auth_service = AuthService(user_repo, audit_repo)
        return await auth_service.refresh_token(request, token, response)
    except AuthError as e:
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
    token: Token,
    audit_repo: AuditRepo,
    user_repo: UserRepo,
) -> None:
    """Logout user and revoke current session following RFC 7009.

    Args:
        request: FastAPI request
        response: FastAPI response
        current_user: Current authenticated user
        token: Access token
        audit_repo: Audit log repository
        user_repo: User repository

    Raises:
        HTTPException: If logout fails
    """
    try:
        auth_service = AuthService(user_repo, audit_repo)
        await auth_service.logout(request, response, current_user, token)
    except AuthError as e:
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
        auth_service = AuthService(user_repo, audit_repo)
        await auth_service.request_password_reset(request, reset_request.email)
        return {"message": "Password reset email sent"}
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
        auth_service = AuthService(user_repo, audit_repo)
        await auth_service.verify_password_reset(
            request=request,
            token=reset_verify.token,
            new_password=reset_verify.password,
        )
        return {"message": "Password reset successful"}
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
