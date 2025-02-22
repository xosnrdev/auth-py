from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.v1 import router as api_v1_router
from app.core.middleware import (
    CSRFMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    setup_cors,
)
from app.core.redis import close_redis, init_redis
from app.db.base import engine
from app.models import Base


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Lifespan context manager for FastAPI application.

    Handles startup and shutdown events:
    - Database initialization
    - Redis connection setup
    """
    # Startup
    try:
        # Initialize database
        async with engine.begin() as conn:
            # await conn.run_sync(Base.metadata.drop_all)  # Uncomment to reset DB
            await conn.run_sync(Base.metadata.create_all)

        # Initialize Redis
        await init_redis()

        yield

    finally:
        # Shutdown
        if isinstance(engine, AsyncEngine):
            await engine.dispose()
        await close_redis()


app = FastAPI(
    title="Authentication Service",
    description="RFC IETF Compliant Authentication Service",
    version="0.1.0",
    lifespan=lifespan,
)

# Security middleware stack (order matters)
app.add_middleware(SecurityHeadersMiddleware)  # Add security headers first
app.add_middleware(CSRFMiddleware)  # CSRF protection
app.add_middleware(RateLimitMiddleware)  # Rate limiting last to avoid unnecessary processing

# CORS middleware with secure defaults
setup_cors(app)

# Include API routes
app.include_router(api_v1_router, prefix="/api")


@app.get("/")
async def read_root() -> dict[str, str]:
    """Root endpoint for health checks."""
    return {"message": "Authentication Service is running"}
