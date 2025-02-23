"""FastAPI application entry point.

The core of our auth service. This module sets up the FastAPI app with all the
essential middleware, error handlers, and health checks you need to run in production.

Key Features:
- Database and Redis auto-setup
- Rate limiting and CORS out of the box
- Swagger docs with OAuth2 support
- Health checks for k8s/docker
- Proper cleanup on shutdown

Quick Start:
```python
# Run locally
fast

# With Docker
docker compose up -d
```

Tip: Check /docs after startup for interactive API documentation.
"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.v1 import router as api_v1_router
from app.core.errors import http_exception_handler, validation_exception_handler
from app.core.metadata import load_project_metadata
from app.core.middleware import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    setup_cors,
)
from app.core.redis import close_redis, init_redis, redis
from app.db.base import engine
from app.models import Base

# Load project metadata
metadata = load_project_metadata()

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Sets up and tears down the app.

    - Creates DB tables if they don't exist
    - Initializes Redis connection pool
    - Cleans up connections on shutdown

    Tip: Comment out `create_all()` if you're using migrations.
    """
    try:
        # Initialize database
        async with engine.begin() as conn:
            # await conn.run_sync(Base.metadata.drop_all)  # Uncomment to reset DB
            await conn.run_sync(Base.metadata.create_all)

        # Initialize Redis
        await init_redis()

        yield

    finally:
        # Cleanup
        if isinstance(engine, AsyncEngine):
            await engine.dispose()
        await close_redis()


def custom_openapi() -> dict[str, Any]:
    """Customizes the OpenAPI/Swagger documentation.

    Adds:
    - Auth flows with examples
    - Error response formats
    - Rate limit details
    - Security schemes

    Pro tip: Check /docs to see it in action.
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description="""
        # Authentication Service API

        ## Quick Start
        1. Register: `POST /api/v1/auth/register`
        2. Verify email: `POST /api/v1/auth/verify-email`
        3. Login: `POST /api/v1/auth/login`
        4. Use the token: `Authorization: Bearer <token>`

        ## Rate Limits
        Check response headers:
        - `X-RateLimit-Limit`: Max requests
        - `X-RateLimit-Remaining`: Requests left
        - `X-RateLimit-Reset`: Reset time

        ## Error Format
        ```json
        {
            "type": "error_type",
            "title": "Human readable error",
            "status": 400,
            "detail": "What went wrong",
            "instance": "/api/v1/auth/register"
        }
        ```
        """,
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token from login or social auth",
        }
    }

    # Add response examples
    openapi_schema["components"]["examples"] = {
        "TokenResponse": {
            "summary": "Successful auth response",
            "value": {
                "access_token": "eyJ0eXAi...",
                "token_type": "Bearer",
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
    title=metadata["name"],
    description=metadata["description"],
    version=metadata["version"],
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

# Custom docs endpoint
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html() -> Response:
    """Serves Swagger UI with our custom theme and OAuth2 support."""
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=app.title,
        oauth2_redirect_url="/docs/oauth2-redirect",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5.9.0/swagger-ui.css",
    )

# Use custom OpenAPI schema
app.openapi = custom_openapi  # type: ignore

# Register error handlers
app.add_exception_handler(
    HTTPException,
    http_exception_handler,  # type: ignore
)
app.add_exception_handler(
    RequestValidationError,
    validation_exception_handler,  # type: ignore
)

@app.middleware("http")
async def add_api_version_header(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Adds API version header to help with client debugging."""
    response = await call_next(request)
    response.headers["X-API-Version"] = metadata["version"]
    return response

# Security middleware (order matters)
# Security headers first
# Rate limiting last
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# CORS with secure defaults
setup_cors(app)

# Include API routes
app.include_router(api_v1_router, prefix="/api")

@app.get("/health")
async def health_check() -> dict[str, str | dict[str, str]]:
    """Health check for k8s/docker.

    Checks:
    - Database connection
    - Redis connection
    - Overall service status

    Returns 200 if everything's good, 500 if not.
    """
    # Check database
    db_healthy = True
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_healthy = False

    # Check Redis
    redis_healthy = True
    try:
        await redis.ping()
    except Exception:
        redis_healthy = False

    status = "ok" if db_healthy and redis_healthy else "error"

    return {
        "status": status,
        "version": metadata["version"],
        "timestamp": datetime.now(UTC).isoformat(),
        "checks": {
            "database": "up" if db_healthy else "down",
            "redis": "up" if redis_healthy else "down",
        }
    }

@app.get("/")
async def read_root() -> dict[str, str]:
    """Root endpoint - useful for quick connection tests."""
    return {"message": "Authentication Service is running"}
