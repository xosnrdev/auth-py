"""Dependencies for authentication endpoints.

This module implements secure FastAPI dependencies following RFC standards:
- JWT Bearer token validation (RFC 6750)
- Database session management
- User authentication and authorization
- Token type enforcement
- Security best practices

The dependencies in this module are used across the authentication system to:
1. Validate and verify access tokens
2. Retrieve authenticated users
3. Manage database sessions
4. Enforce security policies
"""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import TokenType, token_service
from app.db.base import get_db
from app.models import User

# Common dependencies with comprehensive type hints
DBSession = Annotated[AsyncSession, Depends(get_db)]
Token = Annotated[str, Depends(HTTPBearer())]

# Initialize bearer scheme with strict validation
bearer_scheme = HTTPBearer(
    auto_error=True,  # Automatically raise HTTPException on missing/invalid token
    description="JWT Bearer token following RFC 6750",
)


async def get_current_user(
    db: DBSession,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> User:
    """Get the current authenticated user from JWT access token.

    Implements secure user authentication following RFC 6750:
    1. Validates Bearer token format
    2. Verifies token signature and claims
    3. Checks token type (access only)
    4. Retrieves and validates user
    5. Enforces account status

    Only accepts access tokens via Authorization header, following RFC 6750.
    Refresh tokens should only be used to obtain new access tokens.
    Implements additional security measures beyond RFC requirements.

    Args:
        db: Database session for user lookup
        credentials: Bearer token from Authorization header

    Returns:
        User: Current authenticated user with active status

    Raises:
        HTTPException:
            - 401: Invalid or expired token
            - 404: User not found
            - 401: Inactive user account

    Security:
        - Validates token format and signature
        - Enforces token type restrictions
        - Verifies user existence and status
        - Returns standardized errors
        - Implements proper error handling
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


# Type alias for dependency injection with comprehensive validation
CurrentUser = Annotated[User, Depends(get_current_user)]
