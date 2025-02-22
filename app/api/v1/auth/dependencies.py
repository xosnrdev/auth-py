"""Dependencies for authentication endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import get_session
from app.db.base import get_db
from app.models import User

# Common dependencies
DBSession = Annotated[AsyncSession, Depends(get_db)]


async def get_current_user(
    db: DBSession,
    session: str | None = Cookie(None, alias="session"),
) -> User:
    """Get the current authenticated user from session cookie.

    Args:
        db: Database session
        session: Session cookie value

    Returns:
        User: Current authenticated user

    Raises:
        HTTPException: If session is invalid or user not found
    """
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Get user ID from Redis session
    user_id = await get_session(session)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired",
        )

    # Get user from database
    stmt = select(User).where(
        User.id == UUID(user_id),
        User.is_active.is_(True),
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
