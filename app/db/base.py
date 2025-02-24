"""Async PostgreSQL database configuration and session management.

Example:
```python
# In FastAPI dependency
async def get_users(db: AsyncSession = Depends(get_db)):
    query = select(User)
    result = await db.execute(query)
    return result.scalars().all()

# Manual session usage
async with AsyncSessionLocal() as db:
    user = User(email="user@example.com")
    db.add(user)
    await db.commit()
```

Critical Notes:
- Connection pool: 10 base, 20 overflow
- Health checks enabled (pool_pre_ping)
- Sessions don't expire on commit
- Manual flush required
- Connections auto-closed
- Transactions auto-rollback on error
"""

from collections.abc import AsyncGenerator
from typing import Final

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

# Constants
POOL_SIZE: Final[int] = 10
MAX_OVERFLOW: Final[int] = 20
POOL_TIMEOUT: Final[int] = 30  # seconds

# Create async engine with connection pooling
engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URI.unicode_string(),
    echo=settings.DEBUG,  # Log SQL in debug mode
    pool_pre_ping=True,  # Health checks
    pool_size=POOL_SIZE,
    max_overflow=MAX_OVERFLOW,
    pool_timeout=POOL_TIMEOUT,
)

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Keep objects usable after commit
    autoflush=False,  # Explicit flush only
)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Get database session for dependency injection."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()  # Auto-commit if no errors
        except Exception:
            await session.rollback()  # Auto-rollback on error
            raise
        finally:
            await session.close()  # Always close
