from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    """Base class for all database models."""


# Create async engine
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URI.unicode_string(),
    echo=True,  # Set to True for SQL query logging
    pool_pre_ping=True,  # Enable connection health checks
    pool_size=10,  # Maximum number of connections in the pool
    max_overflow=20,  # Maximum number of connections that can be created beyond pool_size
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Don't expire objects after commit
    autoflush=False,  # Don't auto flush changes
)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Dependency for getting async database sessions.

    Yields:
        AsyncSession: SQLAlchemy async session
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
