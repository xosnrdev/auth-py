"""FastAPI application entry point."""

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Final

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.v1 import router as api_v1_router
from app.core.config import settings
from app.core.errors import http_error_handler, validation_error_handler
from app.core.middleware import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    setup_cors,
)
from app.db.postgres import engine
from app.db.redis import close_redis, init_redis, redis
from app.models import Base

HEALTH_STATUS_HEALTHY: Final[str] = "healthy"
HEALTH_STATUS_UNHEALTHY: Final[str] = "unhealthy"
HEALTH_STATUS_CONNECTED: Final[str] = "connected"
HEALTH_STATUS_ERROR: Final[str] = "error"

OPENAPI_BEARER_FORMAT: Final[str] = "JWT"
OPENAPI_AUTH_SCHEME: Final[str] = "bearer"
OPENAPI_AUTH_TYPE: Final[str] = "http"

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Application lifecycle manager."""
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        await init_redis()

        yield

    finally:
        if isinstance(engine, AsyncEngine):
            await engine.dispose()
        await close_redis()


def custom_openapi() -> dict[str, Any]:
    """Custom OpenAPI schema with security focus."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": OPENAPI_AUTH_TYPE,
            "scheme": OPENAPI_AUTH_SCHEME,
            "bearerFormat": OPENAPI_BEARER_FORMAT,
            "description": "JWT token from login or social auth",
        }
    }

    openapi_schema["components"]["examples"] = {
        "TokenResponse": {
            "summary": "Successful auth response",
            "value": {
                "access_token": "eyJ0eXAi...",
                "token_type": OPENAPI_AUTH_SCHEME,
                "expires_in": 900,
                "refresh_token": "def502...",
            },
        },
        "ValidationError": {
            "summary": "Validation error",
            "value": {
                "type": "validation_error",
                "title": "Validation Error",
                "status": 422,
                "detail": "Password too short",
                "instance": "/api/v1/auth/register",
                "errors": [
                    {
                        "loc": ["body", "password"],
                        "msg": "min length 8",
                        "type": "value_error",
                    }
                ],
            },
        },
        "RateLimitError": {
            "summary": "Rate limit hit",
            "value": {
                "type": "rate_limit",
                "title": "Too Many Requests",
                "status": 429,
                "detail": "Try again in 30 seconds",
                "instance": "/api/v1/auth/login",
            },
        },
    }

    app.openapi_schema = openapi_schema
    return openapi_schema


app = FastAPI(
    title=settings.PROJECT_NAME,
    description=settings.PROJECT_DESCRIPTION,
    version=settings.PROJECT_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html() -> Response:
    """Secure Swagger UI implementation."""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=app.title,
        oauth2_redirect_url="/docs/oauth2-redirect",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css",
    )

app.openapi = custom_openapi  # type: ignore

app.add_exception_handler(
    HTTPException,
    http_error_handler,  # type: ignore
)
app.add_exception_handler(
    RequestValidationError,
    validation_error_handler,  # type: ignore
)

@app.middleware("http")
async def add_api_version_header(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Add API version for tracking."""
    response = await call_next(request)
    response.headers["X-API-Version"] = settings.PROJECT_VERSION
    return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

setup_cors(app)

app.include_router(api_v1_router, prefix="/api")

@app.get("/health")
async def health_check() -> dict[str, str | dict[str, str]]:
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

    status = HEALTH_STATUS_HEALTHY if db_healthy and redis_healthy else HEALTH_STATUS_UNHEALTHY
    timestamp = datetime.now(UTC).isoformat()

    return {
        "status": status,
        "checks": {
            "database": HEALTH_STATUS_CONNECTED if db_healthy else HEALTH_STATUS_ERROR,
            "redis": HEALTH_STATUS_CONNECTED if redis_healthy else HEALTH_STATUS_ERROR,
            "timestamp": timestamp,
        },
    }

@app.get("/")
async def read_root() -> dict[str, str]:
    """Root endpoint with API info."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "docs_url": "/docs",
    }
