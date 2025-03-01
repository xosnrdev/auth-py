"""Admin endpoints for user and role management."""

import logging
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status

from app.api.v1.dependencies import AuditRepo, CurrentUser, UserRepo
from app.core.auth import requires_admin, requires_super_admin
from app.core.errors import NotFoundError
from app.core.security import get_password_hash
from app.models import User
from app.schemas import UserResponse, UserUpdate
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["admin"])


@router.get("", response_model=list[UserResponse])
@requires_admin
async def list_users(
    user_repo: UserRepo,
    _: CurrentUser,
    skip: int = 0,
    limit: int = 100,
) -> list[User]:
    """List all users with pagination.

    Args:
        user_repo: User repository
        _: Current authenticated user (unused)
        skip: Number of records to skip
        limit: Maximum number of records to return

    Returns:
        List of users
    """
    return await user_repo.get_all(offset=skip, limit=limit)


@router.get("/{user_id}", response_model=UserResponse)
@requires_admin
async def get_user(
    user_id: UUID,
    user_repo: UserRepo,
    _: CurrentUser,
) -> User:
    """Get specific user details.

    Args:
        user_id: User ID to get
        user_repo: User repository
        _: Current authenticated user (unused)

    Returns:
        User details

    Raises:
        HTTPException: If user not found
    """
    try:
        return await user_repo.get_by_id(user_id)
    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )


@router.patch("/{user_id}", response_model=UserResponse)
@requires_admin
async def update_user(
    request: Request,
    user_id: UUID,
    user_update: UserUpdate,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> User:
    """Update user details.

    Args:
        request: FastAPI request
        user_id: User ID to update
        user_update: User update data
        user_repo: User repository
        audit_repo: Audit log repository
        current_user: Current authenticated user

    Returns:
        Updated user

    Raises:
        HTTPException: If user not found or update fails
    """
    try:
        # Get user first to ensure they exist
        user = await user_repo.get_by_id(user_id)

        # Prepare update data
        update_data = user_update.model_dump(exclude_unset=True)
        if "password" in update_data:
            update_data["password_hash"] = get_password_hash(update_data.pop("password"))

        # Handle verification status
        if user_update.is_verified:
            update_data.update({
                "verification_code": None,
                "verification_code_expires_at": None,
            })

        # Update user
        user = await user_repo.update(user_id, update_data)

        # Log update
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "update_user",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": f"Updated user {user.email}",
        })

        return user

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


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
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
        audit_repo: Audit log repository
        current_user: Current authenticated user

    Raises:
        HTTPException: If user not found or deletion fails
    """
    try:
        # Get user first to ensure they exist and get email for audit log
        user = await user_repo.get_by_id(user_id)

        # Log deletion first in case user deletion fails
        await audit_repo.create({
            "user_id": current_user.id,
            "action": "delete_user",
            "ip_address": get_client_ip(request),
            "user_agent": request.headers.get("user-agent", ""),
            "details": f"Deleted user {user.email}",
        })

        # Delete user
        await user_repo.delete(user_id)

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


@router.post("/{user_id}/roles/{role}", status_code=status.HTTP_200_OK)
@requires_super_admin
async def add_role(
    request: Request,
    user_id: UUID,
    role: str,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> dict[str, list[str]]:
    """Add role to user.

    Args:
        request: FastAPI request
        user_id: User ID to update
        role: Role to add
        user_repo: User repository
        audit_repo: Audit log repository
        current_user: Current authenticated user

    Returns:
        Updated roles list

    Raises:
        HTTPException: If user not found or role update fails
    """
    try:
        # Get user first to ensure they exist
        user = await user_repo.get_by_id(user_id)

        # Add role if not present
        if role not in user.roles:
            roles = user.roles + [role]
            user = await user_repo.update(user_id, {"roles": roles})

            # Log role addition
            await audit_repo.create({
                "user_id": current_user.id,
                "action": "add_role",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Added role {role} to user {user.email}",
            })

        return {"roles": user.roles}

    except NotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    except Exception as e:
        logger.error("Role addition failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to add role",
        )


@router.delete("/{user_id}/roles/{role}", status_code=status.HTTP_200_OK)
@requires_super_admin
async def remove_role(
    request: Request,
    user_id: UUID,
    role: str,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    current_user: CurrentUser,
) -> dict[str, list[str]]:
    """Remove role from user.

    Args:
        request: FastAPI request
        user_id: User ID to update
        role: Role to remove
        user_repo: User repository
        audit_repo: Audit log repository
        current_user: Current authenticated user

    Returns:
        Updated roles list

    Raises:
        HTTPException: If user not found or role update fails
    """
    try:
        # Get user first to ensure they exist
        user = await user_repo.get_by_id(user_id)

        # Remove role if present and not 'user'
        if role in user.roles and role != "user":
            roles = [r for r in user.roles if r != role]
            user = await user_repo.update(user_id, {"roles": roles})

            # Log role removal
            await audit_repo.create({
                "user_id": current_user.id,
                "action": "remove_role",
                "ip_address": get_client_ip(request),
                "user_agent": request.headers.get("user-agent", ""),
                "details": f"Removed role {role} from user {user.email}",
            })

        return {"roles": user.roles}

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


@router.get("/roles", response_model=list[str])
@requires_admin
async def list_roles(
    _: CurrentUser,
) -> list[str]:
    """List available roles.

    Args:
        _: Current authenticated user (unused)

    Returns:
        List of available roles
    """
    return ["user", "admin", "super"]
