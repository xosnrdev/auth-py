from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.v1 import router as api_v1_router
from app.core.errors import http_exception_handler, validation_exception_handler
from app.core.middleware import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    setup_cors,
)
from app.core.redis import close_redis, init_redis, redis
from app.db.base import engine
from app.models import Base

API_VERSION = "1.0.0"

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


def custom_openapi() -> dict:
    """Generate custom OpenAPI schema with examples and authentication flows."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description="""
        # Authentication Service API Documentation

        This API provides authentication and user management functionality following RFC standards.

        ## Authentication Flows

        ### Email/Password Authentication
        1. Register a new account (`POST /api/v1/auth/register`)
        2. Verify email using the code sent (`POST /api/v1/auth/verify-email`)
        3. Login to get access token (`POST /api/v1/auth/login`)
        4. Use access token in Authorization header (`Bearer <token>`)
        5. Refresh token when expired (`POST /api/v1/auth/refresh`)

        ### Social Authentication
        1. Get authorization URL (`GET /api/v1/auth/social/{provider}/authorize`)
        2. Complete OAuth flow (`GET /api/v1/auth/social/{provider}/callback`)
        3. Use returned access token

        ## Rate Limiting
        All endpoints are rate limited. Limits are specified in headers:
        - `X-RateLimit-Limit`: Maximum requests allowed
        - `X-RateLimit-Remaining`: Requests remaining
        - `X-RateLimit-Reset`: Timestamp when limit resets
        - `X-RateLimit-Window`: Time window for limit

        ## Error Responses
        All error responses follow RFC 7807 Problem Details format:
        ```json
        {
            "type": "https://example.com/problems/constraint-violation",
            "title": "The request parameters failed validation",
            "status": 400,
            "detail": "Password must be at least 8 characters long",
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
            "description": "JWT token obtained from login or social auth",
        }
    }

    # Add response examples
    openapi_schema["components"]["examples"] = {
        "TokenResponse": {
            "summary": "Successful authentication response",
            "value": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                "token_type": "Bearer",
                "expires_in": 900,
                "refresh_token": "def502...",
            },
        },
        "ValidationError": {
            "summary": "Validation error response",
            "value": {
                "type": "https://fastapi.tiangolo.com/tutorial/handling-errors/#validation-errors",
                "title": "Request Validation Error",
                "status": 422,
                "detail": "The request parameters failed validation",
                "instance": "/api/v1/auth/register",
                "errors": [
                    {
                        "loc": ["body", "password"],
                        "msg": "Password must be at least 8 characters long",
                        "type": "value_error",
                    }
                ],
            },
        },
        "RateLimitError": {
            "summary": "Rate limit exceeded error",
            "value": {
                "type": "https://tools.ietf.org/html/rfc6585#section-4",
                "title": "Too Many Requests",
                "status": 429,
                "detail": "Rate limit exceeded. Please wait 30 seconds before retrying.",
                "instance": "/api/v1/auth/login",
            },
        },
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app = FastAPI(
    title="Authentication Service",
    description="RFC IETF Compliant Authentication Service",
    version=API_VERSION,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

# Custom documentation endpoints
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html() -> Response:
    """Serve custom Swagger UI."""
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
    """Add API version header to all responses."""
    response = await call_next(request)
    response.headers["X-API-Version"] = API_VERSION
    return response

# Security middleware stack (order matters)
app.add_middleware(SecurityHeadersMiddleware)  # Add security headers first
app.add_middleware(RateLimitMiddleware)  # Rate limiting last to avoid unnecessary processing

# CORS middleware with secure defaults
setup_cors(app)

# Include API routes
app.include_router(api_v1_router, prefix="/api")

@app.get("/health")
async def health_check() -> dict[str, str | dict]:
    """Health check endpoint following RFC health check standard."""
    # Check database connection
    db_healthy = True
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        db_healthy = False

    # Check Redis connection
    redis_healthy = True
    try:
        await redis.ping()
    except Exception:
        redis_healthy = False

    status = "ok" if db_healthy and redis_healthy else "error"

    return {
        "status": status,
        "version": API_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "checks": {
            "database": "up" if db_healthy else "down",
            "redis": "up" if redis_healthy else "down",
        }
    }

@app.get("/")
async def read_root() -> dict[str, str]:
    """Root endpoint for health checks."""
    return {"message": "Authentication Service is running"}
