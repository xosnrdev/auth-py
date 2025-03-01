"""Database dependencies for FastAPI."""

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.repositories import AuditLogRepository, UserRepository

DB = Annotated[AsyncSession, Depends(get_db)]


async def get_user_repository(db: DB) -> UserRepository:
    """Get user repository instance.

    Args:
        db: Database session

    Returns:
        User repository instance
    """
    return UserRepository(db)


async def get_audit_repository(db: DB) -> AuditLogRepository:
    """Get audit log repository instance.

    Args:
        db: Database session

    Returns:
        Audit log repository instance
    """
    return AuditLogRepository(db)


UserRepo = Annotated[UserRepository, Depends(get_user_repository)]
AuditRepo = Annotated[AuditLogRepository, Depends(get_audit_repository)]

__all__ = ["DB", "UserRepo", "AuditRepo"]
