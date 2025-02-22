"""Dependencies for authentication endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import TokenType, token_service
from app.db.base import get_db
from app.models import User

# Common dependencies
DBSession = Annotated[AsyncSession, Depends(get_db)]
Token = Annotated[str, Depends(HTTPBearer())]

# Initialize bearer scheme
bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    db: DBSession,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> User:
    """Get the current authenticated user from JWT access token.

    Only accepts access tokens via Authorization header, following RFC 6750.
    Refresh tokens should only be used to obtain new access tokens.

    Args:
        db: Database session
        credentials: Bearer token from Authorization header

    Returns:
        User: Current authenticated user

    Raises:
        HTTPException: If token is invalid or user not found
    """
    try:
        # Verify access token
        token_data = await token_service.verify_token(credentials.credentials, TokenType.ACCESS)

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
            headers={"WWW-Authenticate": "Bearer"},
        )


CurrentUser = Annotated[User, Depends(get_current_user)]
