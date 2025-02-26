"""Admin endpoints for user and role management."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select

from app.api.v1.dependencies import CurrentUser, DBSession
from app.core.auth import requires_admin, requires_super_admin
from app.core.security import get_password_hash
from app.models import AuditLog, User
from app.schemas import UserResponse, UserUpdate
from app.utils.request import get_client_ip

router = APIRouter(prefix="/users", tags=["admin"])


@router.get("", response_model=list[UserResponse])
@requires_admin
async def list_users(
    db: DBSession,
    _: CurrentUser,
    skip: int = 0,
    limit: int = 100,
) -> list[User]:
    """List all users with pagination."""
    stmt = select(User).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/{user_id}", response_model=UserResponse)
@requires_admin
async def get_user(
    user_id: UUID,
    db: DBSession,
    _: CurrentUser,
) -> User:
    """Get specific user details."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.patch("/{user_id}", response_model=UserResponse)
@requires_admin
async def update_user(
    request: Request,
    user_id: UUID,
    user_update: UserUpdate,
    db: DBSession,
    current_user: CurrentUser,
) -> User:
    """Update user details."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

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


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
@requires_admin
async def delete_user(
    request: Request,
    user_id: UUID,
    db: DBSession,
    current_user: CurrentUser,
) -> None:
    """Delete user."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    audit_log = AuditLog(
        user_id=current_user.id,
        action="delete_user",
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        details=f"Deleted user {user.email}",
    )
    db.add(audit_log)

    await db.delete(user)
    await db.commit()


@router.post("/{user_id}/roles/{role}", status_code=status.HTTP_200_OK)
@requires_super_admin
async def add_role(
    request: Request,
    user_id: UUID,
    role: str,
    db: DBSession,
    current_user: CurrentUser,
) -> dict[str, list[str]]:
    """Add role to user."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if role not in user.roles:
        user.roles.append(role)

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


@router.delete("/{user_id}/roles/{role}", status_code=status.HTTP_200_OK)
@requires_super_admin
async def remove_role(
    request: Request,
    user_id: UUID,
    role: str,
    db: DBSession,
    current_user: CurrentUser,
) -> dict[str, list[str]]:
    """Remove role from user."""
    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if role in user.roles and role != "user":
        user.roles.remove(role)

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
    _: CurrentUser,
) -> list[str]:
    """List available roles."""
    return ["user", "admin", "super"]
