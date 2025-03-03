"""Token dependencies for FastAPI."""

from typing import Annotated

from fastapi import Depends

from app.repositories.token import TokenRepository
from app.services.token import TokenService


async def get_token_repository() -> TokenRepository:
    """Get token repository instance.

    Returns:
        Token repository instance
    """
    return TokenRepository()


async def get_token_service(token_repo: "TokenRepo") -> TokenService:
    """Get token service instance.

    Args:
        token_repo: Token repository

    Returns:
        Token service instance
    """
    return TokenService(token_repo)


TokenRepo = Annotated[TokenRepository, Depends(get_token_repository)]

__all__ = ["TokenRepo", "get_token_service"]
