"""Authentication utilities and decorators.

This module implements secure authentication utilities following RFC standards:
- Role-based access control (RBAC)
- Permission checking
- Security decorators
"""

from collections.abc import Awaitable, Callable
from enum import Enum
from functools import wraps
from typing import Annotated, ParamSpec, TypeVar

from fastapi import Depends, HTTPException, status

from app.api.v1.dependencies import get_current_user
from app.models import User

# Type variables for generic function signatures
P = ParamSpec("P")
T = TypeVar("T")


class RequireMode(str, Enum):
    """Mode for role requirement checking.

    Modes:
        ANY: User must have any of the required roles
        ALL: User must have all required roles
    """

    ANY = "any"
    ALL = "all"


def requires(
    *roles: str,
    mode: RequireMode = RequireMode.ANY,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Decorator for requiring specific roles to access a route.

    Args:
        *roles: Required roles
        mode: How to check roles (any or all)

    Returns:
        Callable: Decorated function

    Example:
        @app.get("/admin")
        @requires("admin")
        async def admin_route():
            return {"message": "Admin only"}

        @app.get("/super-admin")
        @requires("admin", "super", mode=RequireMode.ALL)
        async def super_admin_route():
            return {"message": "Super admin only"}
    """

    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            # Get current user from context
            user = kwargs.get("current_user")
            if not user or not isinstance(user, User):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                )

            # Check roles based on mode
            has_permission = (
                user.has_any_role(list(roles))
                if mode == RequireMode.ANY
                else user.has_all_roles(list(roles))
            )

            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def check_roles(
    roles: list[str],
    mode: RequireMode = RequireMode.ANY,
) -> Callable[[User], bool]:
    """Create a role checker dependency.

    Args:
        roles: Required roles
        mode: How to check roles (any or all)

    Returns:
        Callable: Role checker function

    Example:
        @app.get("/admin")
        async def admin_route(
            _: bool = Depends(check_roles(["admin"])),
        ):
            return {"message": "Admin only"}
    """

    def role_checker(user: Annotated[User, Depends(get_current_user)]) -> bool:
        """Check if user has required roles.

        Args:
            user: Current authenticated user

        Returns:
            bool: True if user has required roles

        Raises:
            HTTPException: If user lacks required roles
        """
        has_permission = (
            user.has_any_role(roles)
            if mode == RequireMode.ANY
            else user.has_all_roles(roles)
        )

        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return True

    return role_checker


# Common role requirements
requires_admin = requires("admin")
requires_super_admin = requires("admin", "super", mode=RequireMode.ALL)
check_admin = check_roles(["admin"])
check_super_admin = check_roles(["admin", "super"], mode=RequireMode.ALL)
