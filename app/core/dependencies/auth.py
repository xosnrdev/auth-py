"""Authentication dependency injection utilities."""

import logging
from typing import Annotated, Final
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.dependencies.database import AuditRepo, UserRepo
from app.core.dependencies.token import TokenRepo, get_token_service
from app.core.errors import NotFoundError
from app.models import User
from app.schemas.audit import AuditLogCreate
from app.schemas.token import TokenType
from app.services import AuditService
from app.utils.request import get_client_ip

logger = logging.getLogger(__name__)

MAX_TOKEN_LENGTH: Final[int] = 1024
AUTH_SCHEME: Final[str] = "Bearer"

bearer_scheme = HTTPBearer(
    auto_error=True,
    description="JWT Bearer token following RFC 6750",
    scheme_name=AUTH_SCHEME,
)

Token = Annotated[str, Depends(HTTPBearer(scheme_name=AUTH_SCHEME))]


async def get_current_user(
    request: Request,
    user_repo: UserRepo,
    audit_repo: AuditRepo,
    token_repo: TokenRepo,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> User:
    """Authenticate and return the current user.

    Args:
        request: FastAPI request
        user_repo: User repository
        audit_repo: Audit log repository
        token_repo: Token repository
        credentials: Bearer token credentials

    Returns:
        Authenticated user

    Raises:
        HTTPException: If authentication fails
    """
    token = credentials.credentials
    assert len(token) <= MAX_TOKEN_LENGTH, "Token exceeds maximum length"

    try:
        # Get token service
        token_service = await get_token_service(token_repo)

        # Verify token
        token_data = await token_service.verify_token(token, TokenType.ACCESS)
        assert token_data.sub, "Token missing subject claim"

        # Get user by ID
        user_id = UUID(token_data.sub)
        try:
            user = await user_repo.get_by_id(user_id)
        except NotFoundError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found",
            )

        # Check if user is active
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is inactive",
            )

        # Log authentication
        audit_service = AuditService(audit_repo)
        await audit_service.create_log(
            AuditLogCreate(
                user_id=user.id,
                action="authenticate",
                ip_address=get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
                details="Token authentication successful",
            )
        )

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
