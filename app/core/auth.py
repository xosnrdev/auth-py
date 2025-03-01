"""Authentication utilities and decorators."""

from collections.abc import Awaitable, Callable
from enum import Enum, auto
from functools import wraps
from typing import ParamSpec, TypeVar

from fastapi import HTTPException, status

from app.models import User

P = ParamSpec("P")
T = TypeVar("T")


class RequireMode(Enum):
    """Role requirement mode."""

    ANY = auto()
    ALL = auto()


def check_roles(
    required_roles: list[str],
    *,
    mode: RequireMode = RequireMode.ANY,
) -> Callable[[Callable[P, Awaitable[T]]], Callable[P, Awaitable[T]]]:
    """Check if user has required roles.

    Args:
        required_roles: List of required roles
        mode: Role requirement mode (ANY or ALL)

    Returns:
        Decorator function
    """

    def decorator(
        func: Callable[P, Awaitable[T]],
    ) -> Callable[P, Awaitable[T]]:
        @wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
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

            # Check roles
            if mode == RequireMode.ALL:
                has_roles = all(role in current_user.roles for role in required_roles)
            else:
                has_roles = any(role in current_user.roles for role in required_roles)

            if not has_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


requires_admin = check_roles(["admin"])
requires_super_admin = check_roles(["super_admin"])
