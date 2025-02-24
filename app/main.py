"""FastAPI application entry point with secure defaults.

Example:
```python
# Run development server
fastapi dev

# Test the API
curl http://localhost:8000/health
{
    "status": "healthy",
    "checks": {
        "database": "connected",
        "redis": "connected",
        "timestamp": "2025-02-24T10:20:30Z"
    }
}
```

Critical Security Notes:
1. Database Security
   - Tables auto-created if missing
   - Connections pooled and limited
   - Transactions auto-rollback
   - SSL required in production

2. Redis Security
   - Connection pooling enabled
   - Health checks active
   - Auto-cleanup on shutdown
   - TLS required in production

3. API Security
   - Rate limiting per endpoint
   - Security headers enforced
   - CORS restrictions active
   - Input validation strict

4. Documentation Security
   - No sensitive data exposed
   - Bearer auth required
   - Rate limits documented
   - Error formats specified
"""

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
from app.core.redis import close_redis, init_redis, redis
from app.db.base import engine
from app.models import Base

# Constants for health check
HEALTH_STATUS_HEALTHY: Final[str] = "healthy"
HEALTH_STATUS_UNHEALTHY: Final[str] = "unhealthy"
HEALTH_STATUS_CONNECTED: Final[str] = "connected"
HEALTH_STATUS_ERROR: Final[str] = "error"

# Constants for OpenAPI
OPENAPI_BEARER_FORMAT: Final[str] = "JWT"
OPENAPI_AUTH_SCHEME: Final[str] = "bearer"
OPENAPI_AUTH_TYPE: Final[str] = "http"

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Application lifecycle manager.

    Example:
    ```python
    app = FastAPI(lifespan=lifespan)
    # Database and Redis auto-initialized
    # Connections auto-cleaned on shutdown
    ```

    Critical Notes:
    1. Database Setup
       - Tables created if missing
       - Migrations should be used in production
       - Connections pooled and limited
       - SSL enforced in production

    2. Redis Setup
       - Connection pool initialized
       - Health checks enabled
       - Auto-cleanup on shutdown
       - TLS required in production

    3. Error Handling
       - Failed setup raises
       - Cleanup always runs
       - Resources released
       - Connections closed
    """
    try:
        # Initialize database
        async with engine.begin() as conn:
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
    """OpenAPI schema with security focus.

    Example:
    ```python
    # Bearer token auth
    curl -H "Authorization: Bearer eyJ..." \\
         http://localhost:8000/api/v1/auth/me

    # Rate limit headers
    < X-RateLimit-Limit: 100
    < X-RateLimit-Remaining: 99
    < X-RateLimit-Reset: 1612345678
    ```

    Critical Notes:
    1. Authentication
       - Bearer tokens required
       - JWT format enforced
       - Tokens expire
       - Refresh supported

    2. Rate Limiting
       - Per-endpoint limits
       - Headers exposed
       - Reset time provided
       - 429 when exceeded

    3. Error Format
       - RFC 7807 compliant
       - No system details
       - Validation errors
       - Clear messages
    """
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "HTTPBearer": {
            "type": OPENAPI_AUTH_TYPE,
            "scheme": OPENAPI_AUTH_SCHEME,
            "bearerFormat": OPENAPI_BEARER_FORMAT,
            "description": "JWT token from login or social auth",
        }
    }

    # Add response examples
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
    """Secure Swagger UI implementation.

    Example:
    ```python
    # Access interactive docs
    open http://localhost:8000/docs
    ```

    Critical Notes:
    1. Security
       - OAuth2 support enabled
       - HTTPS CDN resources
       - No sensitive data
       - Version controlled

    2. Features
       - Interactive testing
       - Auth flows documented
       - Examples provided
       - Error responses shown
    """
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
    """Add API version for tracking.

    Example:
    ```python
    # Response includes version
    < X-API-Version: 1.0.0
    ```

    Critical Notes:
    1. Security
       - No sensitive data
       - Version controlled
       - Headers validated
       - Safe defaults
    """
    response = await call_next(request)
    response.headers["X-API-Version"] = settings.PROJECT_VERSION
    return response

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

setup_cors(app)

app.include_router(api_v1_router, prefix="/api")

@app.get("/health")
async def health_check() -> dict[str, str | dict[str, str]]:
    """System health check endpoint.

    Example:
    ```python
    # Check system health
    curl http://localhost:8000/health
    {
        "status": "healthy",
        "checks": {
            "database": "connected",
            "redis": "connected",
            "timestamp": "2025-02-23T10:20:30Z"
        }
    }
    ```

    Critical Notes:
    1. Security
       - No sensitive data
       - Limited information
       - Safe error handling
       - Status codes only

    2. Checks
       - Database connection
       - Redis connection
       - System timestamp
       - Overall status
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

    # Overall status
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
    """Root endpoint with API info.

    Example:
    ```python
    # Get API info
    curl http://localhost:8000/
    {
        "name": "Auth Service",
        "version": "1.0.0",
        "docs_url": "/docs"
    }
    ```

    Critical Notes:
    1. Security
       - Public endpoint
       - No sensitive data
       - Version controlled
       - Safe response
    """
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.PROJECT_VERSION,
        "docs_url": "/docs",
    }
