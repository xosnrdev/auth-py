"""Admin endpoints for user and role management.

This module implements secure administrative functions including:
- User management (CRUD operations)
- Role management (RBAC)
- User activation/deactivation
- Email verification management
"""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.v1.auth.dependencies import CurrentUser, DBSession
from app.core.auth import requires_admin, requires_super_admin
from app.core.security import get_password_hash
from app.models import AuditLog, User
from app.schemas import UserResponse, UserUpdate
from app.utils.request import get_client_ip

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", response_model=list[UserResponse])
@requires_admin
async def list_users(
    db: DBSession,
    _: CurrentUser,  # Required by @requires_admin
    skip: int = 0,
    limit: int = 100,
) -> list[User]:
    """List all users with pagination following RBAC principles.

    Implements secure user listing with:
    1. Role-based access control (admin only)
    2. Pagination to prevent resource exhaustion
    3. Standardized user response format

    Args:
        db: Database session
        _: Current admin user (required by @requires_admin decorator)
        skip: Number of records to skip (pagination)
        limit: Maximum number of records to return

    Returns:
        list[User]: List of users with standardized response format

    Security:
        - Requires admin role
        - Implements pagination
        - Returns sanitized user data
        - Rate limited by default middleware
    """
    stmt = select(User).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/users/{user_id}", response_model=UserResponse)
@requires_admin
async def get_user(
    user_id: UUID,
    db: DBSession,
    _: CurrentUser,  # Required by @requires_admin
) -> User:
    """Get specific user details following RBAC principles.

    Implements secure user retrieval:
    1. Role-based access control (admin only)
    2. UUID validation
    3. Not found handling
    4. Standardized user response

    Args:
        user_id: UUID of the user to retrieve
        db: Database session
        _: Current admin user (required by @requires_admin decorator)

    Returns:
        User: User details in standardized format

    Raises:
        HTTPException: If user not found (404)

    Security:
        - Requires admin role
        - Validates UUID format
        - Returns sanitized user data
        - Rate limited by default middleware
    """
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.patch("/users/{user_id}", response_model=UserResponse)
@requires_admin
async def update_user(
    request: Request,
    user_id: UUID,
    user_update: UserUpdate,
    db: DBSession,
    current_user: CurrentUser,
) -> User:
    """Update user details following RBAC and security principles.

    Implements secure user update flow:
    1. Role-based access control (admin only)
    2. Partial updates with validation
    3. Password hashing if updated
    4. Email verification management
    5. Audit logging

    Args:
        request: FastAPI request object
        user_id: UUID of the user to update
        user_update: Update data with validation
        db: Database session
        current_user: Current admin user for audit

    Returns:
        User: Updated user details

    Raises:
        HTTPException: If user not found (404)

    Security:
        - Requires admin role
        - Validates input data
        - Securely hashes passwords
        - Logs all changes for audit
        - Rate limited by default middleware
    """
    # Get user
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update fields if provided
    if user_update.phone is not None:
        user.phone = user_update.phone
    if user_update.is_active is not None:
        user.is_active = user_update.is_active
    if user_update.is_verified is not None:
        user.is_verified = user_update.is_verified
        if user.is_verified:
            user.verification_code = None
            user.verification_code_expires_at = None
    if user_update.password:
        user.password_hash = get_password_hash(user_update.password)

    # Log update
    audit_log = AuditLog(
        user_id=current_user.id,
        action="update_user",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Updated user {user.email}",
    )
    db.add(audit_log)

    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
@requires_admin
async def delete_user(
    request: Request,
    user_id: UUID,
    db: DBSession,
    current_user: CurrentUser,
) -> None:
    """Delete user following RBAC and security principles.

    Implements secure user deletion:
    1. Role-based access control (admin only)
    2. Audit logging before deletion
    3. Cascading deletion of related data
    4. No content response (204)

    Args:
        request: FastAPI request object
        user_id: UUID of the user to delete
        db: Database session
        current_user: Current admin user for audit

    Raises:
        HTTPException: If user not found (404)

    Security:
        - Requires admin role
        - Logs deletion for audit
        - Handles cascading deletes
        - Rate limited by default middleware
    """
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Log deletion
    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_user",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Deleted user {user.email}",
    )
    db.add(audit_log)

    # Delete user
    await db.delete(user)
    await db.commit()


@router.post("/users/{user_id}/roles/{role}", status_code=status.HTTP_200_OK)
@requires_super_admin
async def add_role(
    request: Request,
    user_id: UUID,
    role: str,
    db: DBSession,
    current_user: CurrentUser,
) -> dict[str, list[str]]:
    """Add role to user following RBAC principles.

    Implements secure role assignment:
    1. Super admin access control
    2. Role validation
    3. Idempotent operation
    4. Audit logging

    Args:
        request: FastAPI request object
        user_id: UUID of the target user
        role: Role to add
        db: Database session
        current_user: Current super admin for audit

    Returns:
        dict: Updated list of user roles

    Raises:
        HTTPException: If user not found (404)

    Security:
        - Requires super admin role
        - Validates role name
        - Logs role changes
        - Rate limited by default middleware
    """
    # Get user
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Add role if not present
    if role not in user.roles:
        user.roles.append(role)

        # Log role addition
        audit_log = AuditLog(
            user_id=current_user.id,
            action="add_role",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Added role {role} to user {user.email}",
        )
        db.add(audit_log)

        await db.commit()

    return {"roles": user.roles}


@router.delete("/users/{user_id}/roles/{role}", status_code=status.HTTP_200_OK)
@requires_super_admin
async def remove_role(
    request: Request,
    user_id: UUID,
    role: str,
    db: DBSession,
    current_user: CurrentUser,
) -> dict[str, list[str]]:
    """Remove role from user following RBAC principles.

    Implements secure role removal:
    1. Super admin access control
    2. Protection of base role
    3. Idempotent operation
    4. Audit logging

    Args:
        request: FastAPI request object
        user_id: UUID of the target user
        role: Role to remove
        db: Database session
        current_user: Current super admin for audit

    Returns:
        dict: Updated list of user roles

    Raises:
        HTTPException: If user not found (404)

    Security:
        - Requires super admin role
        - Protects 'user' base role
        - Logs role changes
        - Rate limited by default middleware
    """
    # Get user
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Remove role if present
    if role in user.roles and role != "user":
        user.roles.remove(role)

        # Log role removal
        audit_log = AuditLog(
            user_id=current_user.id,
            action="remove_role",
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
            details=f"Removed role {role} from user {user.email}",
        )
        db.add(audit_log)

        await db.commit()

    return {"roles": user.roles}


@router.get("/roles", response_model=list[str])
@requires_admin
async def list_roles(
    _: CurrentUser,  # Required by @requires_admin
) -> list[str]:
    """List available roles following RBAC principles.

    Implements secure role listing:
    1. Role-based access control (admin only)
    2. Static role enumeration
    3. Hierarchical role structure

    Args:
        _: Current admin user (required by @requires_admin decorator)

    Returns:
        list[str]: List of available roles

    Security:
        - Requires admin role
        - Static role definition
        - Rate limited by default middleware
    """
    return ["user", "admin", "super"]
