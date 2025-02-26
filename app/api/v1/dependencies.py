"""FastAPI dependency injection utilities for authentication and database access."""

import logging
from typing import Annotated, Final
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.jwt import TokenType, token_service
from app.db.postgres import get_db
from app.models import User
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

MAX_TOKEN_LENGTH: Final[int] = 1024
AUTH_SCHEME: Final[str] = "Bearer"

DBSession = Annotated[AsyncSession, Depends(get_db)]
Token = Annotated[str, Depends(HTTPBearer())]

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
    """Authenticate and return the current user."""
    token = credentials.credentials
    assert len(token) <= MAX_TOKEN_LENGTH, "Token exceeds maximum length"

    try:
        token_data = await token_service.verify_token(token, TokenType.ACCESS)
        assert token_data.sub, "Token missing subject claim"

        user_id = UUID(token_data.sub)
        stmt = select(User).where(
            User.id == user_id,
            User.is_active.is_(True),
        )
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )
        assert user.is_active, "User account is inactive"

        return user

    except AssertionError as e:
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


CurrentUser = Annotated[User, Depends(get_current_user)]
