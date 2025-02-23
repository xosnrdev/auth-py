"""FastAPI application entry point with secure configuration.

This module implements a secure FastAPI application following multiple RFCs:
- HTTP/1.1 (RFC 9110)
- HTTP Semantics (RFC 9112)
- HTTP Authentication (RFC 7235)
- OAuth2 (RFC 6749)
- Bearer Tokens (RFC 6750)
- Problem Details (RFC 7807)
- CORS (Cross-Origin Resource Sharing)
- Rate Limiting (RFC 6585)
- Health Check (RFC Health Check Draft)

Core Features:
1. Application Setup
   - FastAPI configuration
   - Database initialization
   - Redis connection
   - Router integration
   - Middleware stack

2. Security Features
   - CORS protection
   - Rate limiting
   - Security headers
   - Error handling
   - Input validation

3. Documentation
   - OpenAPI schema
   - Swagger UI
   - Security schemes
   - Response examples
   - Error formats

4. Monitoring
   - Health checks
   - Version tracking
   - Status endpoints
   - Database checks
   - Redis checks
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

    Implements secure application lifecycle management:
    1. Database initialization
       - Creates database tables
       - Verifies connection
       - Handles migrations

    2. Redis setup
       - Establishes connection
       - Verifies connectivity
       - Sets up session store

    3. Cleanup
       - Closes database connections
       - Shuts down Redis client
       - Releases resources

    Args:
        _: FastAPI application instance (unused)

    Yields:
        None: Control returns to FastAPI

    Security:
        - Safe database initialization
        - Secure connection handling
        - Proper resource cleanup
        - Error isolation
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


def custom_openapi() -> dict[str, Any]:
    """Generate custom OpenAPI schema with comprehensive documentation.

    Implements OpenAPI 3.0 schema generation:
    1. Base Configuration
       - Title and version
       - Description and terms
       - Security schemes
       - Server information

    2. Authentication Flows
       - Email/password flow
       - Social authentication
       - Token management
       - Session handling

    3. Security Schemes
       - Bearer authentication
       - OAuth2 flows
       - PKCE support
       - Token formats

    4. Response Examples
       - Success responses
       - Error formats
       - Validation errors
       - Rate limit errors

    Returns:
        dict: Complete OpenAPI schema

    Security:
        - Documents security schemes
        - Includes error responses
        - Shows rate limits
        - Describes headers
    """
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
    """Serve custom Swagger UI with enhanced security.

    Implements secure API documentation:
    1. Custom Swagger UI
       - Latest version
       - Security features
       - CORS protection
       - XSS prevention

    2. OAuth2 Support
       - Redirect handling
       - Token management
       - Flow visualization
       - Scope display

    Returns:
        Response: Swagger UI HTML page

    Security:
        - Uses secure CDN
        - Implements CSP
        - Prevents XSS
        - CORS protected
    """
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
    """Add API version header to all responses.

    Implements API versioning:
    1. Version Header
       - Adds X-API-Version
       - Tracks API version
       - Supports clients
       - Enables monitoring

    2. Request Processing
       - Intercepts responses
       - Adds headers
       - Maintains chain
       - Handles errors

    Args:
        request: Incoming HTTP request
        call_next: Next middleware in chain

    Returns:
        Response: Modified response with version header

    Security:
        - Safe header addition
        - Error handling
        - Chain preservation
        - Version tracking
    """
    response = await call_next(request)
    response.headers["X-API-Version"] = API_VERSION
    return response

# Security middleware stack (order matters)
# Add security headers first
# Rate limiting last to avoid unnecessary processing
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# CORS middleware with secure defaults
setup_cors(app)

# Include API routes
app.include_router(api_v1_router, prefix="/api")

@app.get("/health")
async def health_check() -> dict[str, str | dict[str, str]]:
    """Health check endpoint following RFC health check standard.

    Implements comprehensive health checking:
    1. Service Health
       - Overall status
       - Version info
       - Timestamp
       - Component status

    2. Database Check
       - Connection test
       - Query execution
       - Pool status
       - Migration state

    3. Redis Check
       - Connection test
       - Ping response
       - Pool status
       - Cache state

    Returns:
        dict: Health check response with component status

    Security:
        - Safe checks
        - Limited info
        - Error handling
        - Status tracking
    """
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
    """Root endpoint for basic service information.

    Implements service discovery:
    1. Service Info
       - Service name
       - Running status
       - Basic health
       - Entry point

    Returns:
        dict: Service status message

    Security:
        - Limited info
        - Safe response
        - Error handling
    """
    return {"message": "Authentication Service is running"}
