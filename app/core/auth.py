"""Core authentication utilities."""

from collections.abc import Awaitable, Callable
from functools import wraps
from typing import ParamSpec, TypeVar

from fastapi import HTTPException, status

from app.models.user import User, UserRole

P = ParamSpec("P")
T = TypeVar("T")


def check_role(
    required_role: UserRole,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Check if user has required role or higher.

    Args:
        required_role: Minimum required role level

    Returns:
        Decorator that checks role
    """

    def decorator(func: Callable[P, Awaitable[T]]) -> Callable[P, Awaitable[T]]:
        """Decorator that checks role.

        Args:
            func: Function to decorate

        Returns:
            Decorated function
        """

        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            """Check role and call the function."""
            # Get current user from kwargs
            current_user = None
            for value in kwargs.values():
                if isinstance(value, User):
                    current_user = value
                    break

            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required",
                )

            if not current_user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Inactive user",
                )

            if not current_user.role.has_permission(required_role):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


requires_admin = check_role(UserRole.ADMIN)
requires_moderator = check_role(UserRole.MODERATOR)
requires_user = check_role(UserRole.USER)
