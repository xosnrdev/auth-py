"""User management API endpoints."""

import logging

from fastapi import APIRouter, HTTPException, Request, status

from app.core.dependencies import AuditRepo, CurrentUser, UserRepo
from app.core.errors import DuplicateError, UserError
from app.models import User
from app.schemas import EmailRequest, UserCreate, UserResponse, UserUpdate
from app.schemas.user import (
    EmailChangeVerify,
    EmailVerificationRequest,
)
from app.services import UserService

logger = logging.getLogger(__name__)

router = APIRouter(tags=["users"])


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register(
    request: Request,
    user_in: UserCreate,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> User:
    """Register a new user account.

    Args:
        request: FastAPI request
        user_in: User registration data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Created user

    Raises:
        HTTPException: If registration fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        return await user_service.register(request, user_in)
    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/verify-email")
async def verify_email(
    request: Request,
    verification_data: EmailVerificationRequest,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Verify user's email address.

    Args:
        request: FastAPI request
        verification_data: Email verification data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If verification fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        await user_service.verify_email(request, verification_data.code)
        return {"message": "Email verified successfully"}
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/me", response_model=UserResponse)
async def get_profile(current_user: CurrentUser) -> User:
    """Get current user's profile.

    Args:
        current_user: Current authenticated user

    Returns:
        User profile
    """
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_profile(
    request: Request,
    user_update: UserUpdate,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> User:
    """Update current user's profile.

    Args:
        request: FastAPI request
        user_update: User update data
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Updated user profile

    Raises:
        HTTPException: If update fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        return await user_service.update_profile(request, current_user.id, user_update)
    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.delete("/me", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(
    request: Request,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> None:
    """Delete current user's account.

    Args:
        request: FastAPI request
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Raises:
        HTTPException: If deletion fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        await user_service.delete_profile(request, current_user.id)
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/me/verify-email/resend")
async def resend_verification(
    request: Request,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Resend verification email for current user.

    Args:
        request: FastAPI request
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If resend fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        await user_service.resend_verification(request, current_user.id)
        return {"message": "Verification email sent"}
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/verify-email/resend")
async def resend_verification_public(
    request: Request,
    email_in: EmailRequest,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Resend verification email (public endpoint).

    Args:
        request: FastAPI request
        email_in: Email request data
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Note:
        Always returns success to prevent email enumeration
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        await user_service.resend_verification_public(request, email_in.email)
        return {
            "message": "If the email exists and is unverified, "
            "a new verification email has been sent"
        }
    except Exception:
        # Return success even on error to prevent email enumeration
        return {
            "message": "If the email exists and is unverified, "
            "a new verification email has been sent"
        }


@router.post("/me/email", response_model=dict[str, str])
async def request_email_change(
    request: Request,
    email_in: EmailRequest,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> dict[str, str]:
    """Request email address change.

    Args:
        request: FastAPI request
        email_in: Email request data
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Success message

    Raises:
        HTTPException: If request fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        await user_service.request_email_change(
            request, current_user.id, email_in.email
        )
        return {"message": "Verification email sent to new address"}
    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.post("/me/email/verify", response_model=UserResponse)
async def verify_email_change(
    request: Request,
    verification_data: EmailChangeVerify,
    current_user: CurrentUser,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
) -> User:
    """Verify and complete email address change.

    Args:
        request: FastAPI request
        verification_data: Email change verification data
        current_user: Current authenticated user
        user_repo: User repository
        audit_repo: Audit log repository

    Returns:
        Updated user profile

    Raises:
        HTTPException: If verification fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        return await user_service.verify_email_change(
            request, current_user.id, verification_data.code
        )
    except DuplicateError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except UserError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
