"""Dependencies for authentication endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import token_service
from app.db.base import get_db
from app.models import User

# Common dependencies
DBSession = Annotated[AsyncSession, Depends(get_db)]

# Initialize bearer scheme
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    db: DBSession,
    refresh_token: str | None = Cookie(None, alias="session"),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> User:
    """Get the current authenticated user from JWT token.

    Supports both cookie-based (web) and header-based (API) authentication.
    For web clients, uses refresh token from cookie.
    For API clients, uses access token from Authorization header.

    Args:
        db: Database session
        refresh_token: Refresh token from cookie
        credentials: Bearer token from Authorization header

    Returns:
        User: Current authenticated user

    Raises:
        HTTPException: If token is invalid or user not found
    """
    # Check for token in either cookie or header
    if not refresh_token and not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    try:
        # Use refresh token from cookie for web clients
        if refresh_token:
            token_data = await token_service.verify_token(refresh_token, "refresh")
        # Use access token from header for API clients
        elif credentials:
            token_data = await token_service.verify_token(credentials.credentials, "access")
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )

        # Get user from database
        stmt = select(User).where(
            User.id == UUID(token_data.sub),
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

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


CurrentUser = Annotated[User, Depends(get_current_user)]
