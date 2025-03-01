"""Async PostgreSQL database configuration and session management."""

from collections.abc import AsyncGenerator
from typing import Final

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import Environment, settings
from app.models.base import Base

POOL_SIZE: Final[int] = 10
MAX_OVERFLOW: Final[int] = 20
POOL_TIMEOUT: Final[int] = 30

engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URI.unicode_string(),
    echo=settings.ENVIRONMENT == Environment.DEVELOPMENT,
    pool_pre_ping=True,
    pool_size=POOL_SIZE,
    max_overflow=MAX_OVERFLOW,
    pool_timeout=POOL_TIMEOUT,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def init_database() -> None:
    """Initialize database and create all tables."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        raise RuntimeError(f"Failed to initialize database: {e}") from e


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Get database session for dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
