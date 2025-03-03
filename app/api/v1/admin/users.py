"""Admin endpoints for user and role management."""

import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from app.core.auth import requires_admin
from app.core.dependencies import AuditRepo, CurrentUser, UserRepo
from app.core.errors import NotFoundError
from app.models.user import User, UserRole
from app.schemas.user import UserResponse, UserRoleUpdate, UserUpdate
from app.services import UserService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["admin"])


@router.get("/roles", response_model=list[str])
@requires_admin
async def list_roles(
    _: CurrentUser,
) -> list[str]:
    """List available roles.

    Args:
        _: Current authenticated user

    Returns:
        List of available roles
    """
    return [role.value for role in UserRole]


@router.get("", response_model=list[UserResponse])
@requires_admin
async def list_users(
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    _: CurrentUser,
    skip: int = 0,
    limit: int = 20,
    role: UserRole | None = None,
) -> list[User]:
    """List users with optional role filter.

    Args:
        user_repo: User repository
        audit_repo: Audit repository
        _: Current authenticated user
        skip: Number of users to skip
        limit: Maximum number of users to return
        role: Optional role to filter by

    Returns:
        List of users

    Raises:
        HTTPException: If listing fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        if role:
            return await user_service.list_users_by_role(role, skip=skip, limit=limit)
        return await user_service.list_users(skip=skip, limit=limit)
    except Exception as e:
        logger.error("User listing failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to list users",
        )


@router.get("/{user_id}", response_model=UserResponse)
@requires_admin
async def get_user(
    user_id: UUID,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    _: CurrentUser,
) -> User:
    """Get user by ID.

    Args:
        user_id: User ID to get
        user_repo: User repository
        audit_repo: Audit repository
        _: Current authenticated user

    Returns:
        User details

    Raises:
        HTTPException: If user not found
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        return await user_service.get_user(user_id)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except Exception as e:
        logger.error("User retrieval failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to get user",
        )


@router.put("/{user_id}", response_model=UserResponse)
@requires_admin
async def update_user(
    request: Request,
    user_id: UUID,
    user_data: UserUpdate,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> User:
    """Update user details.

    Args:
        request: FastAPI request
        user_id: User ID to update
        user_data: User update data
        user_repo: User repository
        audit_repo: Audit repository
        current_user: Current authenticated user

    Returns:
        Updated user

    Raises:
        HTTPException: If user not found or update fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        return await user_service.admin_update_user(
            request=request,
            user_id=user_id,
            user_data=user_data,
            admin_user=current_user,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except Exception as e:
        logger.error("User update failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update user",
        )


@router.delete(
    "/{user_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None
)
@requires_admin
async def delete_user(
    request: Request,
    user_id: UUID,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> None:
    """Delete user.

    Args:
        request: FastAPI request
        user_id: User ID to delete
        user_repo: User repository
        audit_repo: Audit repository
        current_user: Current authenticated user

    Raises:
        HTTPException: If user not found or deletion fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        await user_service.admin_delete_user(
            request=request,
            user_id=user_id,
            admin_user=current_user,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except Exception as e:
        logger.error("User deletion failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to delete user",
        )


@router.put("/{user_id}/role", response_model=UserResponse)
@requires_admin
async def update_role(
    request: Request,
    user_id: UUID,
    role_update: UserRoleUpdate,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> User:
    """Update user role.

    Args:
        request: FastAPI request
        user_id: User ID to update
        role_update: Role update data
        user_repo: User repository
        audit_repo: Audit repository
        current_user: Current authenticated user

    Returns:
        Updated user

    Raises:
        HTTPException: If user not found or role update fails
    """
    try:
        user_service = UserService(user_repo, audit_repo)
        return await user_service.update_user_role(
            request=request,
            user_id=user_id,
            role=role_update.role,
            admin_user=current_user,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except Exception as e:
        logger.error("Role update failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to update role",
        )


@router.delete("/{user_id}/role/{role}", response_model=UserResponse)
@requires_admin
async def remove_role(
    request: Request,
    user_id: UUID,
    role: str,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> User:
    """Remove role from user.

    Args:
        request: FastAPI request
        user_id: User ID to update
        role: Role to remove
        user_repo: User repository
        audit_repo: Audit repository
        current_user: Current authenticated user

    Returns:
        Updated user

    Raises:
        HTTPException: If user not found or role removal fails
    """
    try:
        # Validate role
        try:
            role_enum = UserRole(role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {role}",
            )

        user_service = UserService(user_repo, audit_repo)
        return await user_service.remove_user_role(
            request=request,
            user_id=user_id,
            role=role_enum,
            admin_user=current_user,
        )
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except Exception as e:
        logger.error("Role removal failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to remove role",
        )
