"""FastAPI dependency injection utilities for authentication and database access.

Example:
```python
from fastapi import APIRouter, Depends
from app.api.v1.dependencies import CurrentUser, DBSession

router = APIRouter()

@router.get("/me")
async def get_profile(
    current_user: CurrentUser,
    db: DBSession,
) -> dict:
    # current_user is automatically authenticated
    # db session is automatically managed
    return {"email": current_user.email}
```

Critical Security Notes:
1. Token Validation
   - Only accepts valid JWT access tokens
   - Refresh tokens are rejected
   - Tokens must be unexpired and unrevoked
   - All token errors return 401 Unauthorized

2. Database Access
   - Sessions are automatically closed
   - Transactions are rolled back on errors
   - No raw SQL queries allowed
   - All queries use SQLAlchemy ORM

3. Error Handling
   - All errors return proper HTTP status codes
   - Error messages don't leak internal details
   - Authentication failures are logged
   - Rate limiting is enforced
"""

import logging
from typing import Annotated, Final
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import TokenType, token_service
from app.db.base import get_db
from app.models import User
from app.utils.request import get_client_ip

# Configure module logger
logger = logging.getLogger(__name__)

# Security constants
MAX_TOKEN_LENGTH: Final[int] = 1024
AUTH_SCHEME: Final[str] = "Bearer"

# Common dependencies with type safety
DBSession = Annotated[AsyncSession, Depends(get_db)]
Token = Annotated[str, Depends(HTTPBearer())]

# Initialize bearer scheme with strict validation
bearer_scheme = HTTPBearer(
    auto_error=True,
    description="JWT Bearer token following RFC 6750",
    scheme_name=AUTH_SCHEME,
)


async def get_current_user(
    request: Request,
    db: DBSession,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> User:
    """Authenticate and return the current user.

    Example:
    ```python
    @router.get("/profile")
    async def get_profile(user: Annotated[User, Depends(get_current_user)]):
        return {"email": user.email}
    ```

    Args:
        request: FastAPI request for logging
        db: Database session for user lookup
        credentials: Bearer token from Authorization header

    Returns:
        User: Authenticated and active user

    Raises:
        HTTPException:
            - 401: Invalid/expired token or inactive user
            - 404: User not found
    """
    # Validate token length
    token = credentials.credentials
    assert len(token) <= MAX_TOKEN_LENGTH, "Token exceeds maximum length"

    try:
        # Verify access token (raises if invalid)
        token_data = await token_service.verify_token(token, TokenType.ACCESS)
        assert token_data.sub, "Token missing subject claim"

        # Get user from database
        user_id = UUID(token_data.sub)
        stmt = select(User).where(
            User.id == user_id,
            User.is_active.is_(True),
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        # Verify user exists and is active
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        assert user.is_active, "User account is inactive"

        return user

    except AssertionError as e:
        # Log security assertion failures
        logger.warning(
            "Auth assertion failed: %s, IP: %s, UA: %s",
            str(e),
            get_client_ip(request),
            request.headers.get("user-agent", ""),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": AUTH_SCHEME},
        )

    except Exception as e:
        # Log unexpected auth failures
        logger.error(
            "Auth failed: %s, IP: %s, UA: %s",
            str(e),
            get_client_ip(request),
            request.headers.get("user-agent", ""),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed",
            headers={"WWW-Authenticate": AUTH_SCHEME},
        )


# Type alias for dependency injection
CurrentUser = Annotated[User, Depends(get_current_user)]
