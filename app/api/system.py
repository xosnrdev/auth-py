"""System-level API routes."""

from typing import Any, Final

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import RedirectResponse
from sqlalchemy import text

from app.core.config import settings
from app.db.postgres import engine
from app.db.redis import redis

# Constants
HEALTH_STATUS_HEALTHY: Final[str] = "healthy"
HEALTH_STATUS_UNHEALTHY: Final[str] = "unhealthy"
HEALTH_STATUS_CONNECTED: Final[str] = "connected"
HEALTH_STATUS_ERROR: Final[str] = "error"

SWAGGER_OAUTH2_REDIRECT_URL: Final[str] = "/docs/oauth2-redirect"

# Create router
router = APIRouter(tags=["System"])


def get_app() -> FastAPI:
    """Get FastAPI app instance for dependency injection."""
    from app.main import app
    return app


@router.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html(app: FastAPI = Depends(get_app)) -> Response:
    """Secure Swagger UI implementation."""
    return get_swagger_ui_html(
        openapi_url="/api/openapi.json",
        title=f"{app.title} - Swagger UI",
        oauth2_redirect_url=SWAGGER_OAUTH2_REDIRECT_URL,
        swagger_js_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css",
    )


@router.get(SWAGGER_OAUTH2_REDIRECT_URL, include_in_schema=False)
async def swagger_ui_redirect(request: Request) -> Response:
    """OAuth2 redirect for Swagger UI."""
    if not any(param in request.query_params for param in ["code", "error", "state"]):
        return RedirectResponse(url="/docs")
    return get_swagger_ui_oauth2_redirect_html()


@router.get("/redoc", include_in_schema=False)
async def redoc_html(app: FastAPI = Depends(get_app)) -> Response:
    """ReDoc UI implementation."""
    return get_redoc_html(
        openapi_url="/api/openapi.json",
        title=f"{app.title} - ReDoc",
        redoc_js_url="https://unpkg.com/redoc@next/bundles/redoc.standalone.js",
    )


@router.get("/api/openapi.json", include_in_schema=False)
async def get_openapi_json(app: FastAPI = Depends(get_app)) -> dict[str, Any]:
    """Get OpenAPI schema."""
    return app.openapi()


@router.get("/health")
async def health_check() -> dict[str, Any]:
    """System health check endpoint."""
    db_healthy = True
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_healthy = False

    redis_healthy = True
    try:
        await redis.ping()
    except Exception:
        redis_healthy = False

    status = (
        HEALTH_STATUS_HEALTHY
        if db_healthy and redis_healthy
        else HEALTH_STATUS_UNHEALTHY
    )

    return {
        "status": status,
        "checks": {
            "database": (
                HEALTH_STATUS_CONNECTED if db_healthy else HEALTH_STATUS_ERROR
            ),
            "redis": HEALTH_STATUS_CONNECTED if redis_healthy else HEALTH_STATUS_ERROR,
        },
    }


@router.get("/")
async def read_root() -> dict[str, str]:
    """Root endpoint with API info."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "docs_url": "/docs",
    }
