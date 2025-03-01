"""System-level API routes."""

import logging
from typing import Final

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine, redis

logger = logging.getLogger(__name__)


HEALTH_STATUS_HEALTHY: Final[str] = "healthy"
HEALTH_STATUS_UNHEALTHY: Final[str] = "unhealthy"
HEALTH_STATUS_CONNECTED: Final[str] = "connected"
HEALTH_STATUS_ERROR: Final[str] = "error"


router = APIRouter(tags=["system"])


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Check system health.

    Returns:
        Health status

    Raises:
        HTTPException: If any system component is unhealthy
    """
    try:
        # Check database connection
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

        # Check Redis connection
        await redis.ping()

        return {"status": HEALTH_STATUS_HEALTHY}

    except Exception as e:
        logger.error("Health check failed: %s", str(e))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"System unhealthy: {str(e)}",
        )


@router.get("/")
async def read_root() -> dict[str, str]:
    """Root endpoint with API info.

    Returns:
        Basic API information
    """
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "environment": settings.ENVIRONMENT.value,
    }
