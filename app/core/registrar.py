"""Application registrar for managing FastAPI initialization and configuration."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, Final

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.api.system import SWAGGER_OAUTH2_REDIRECT_URL
from app.api.system import router as system_router
from app.api.v1 import router as api_v1_router
from app.core.config import settings
from app.core.errors import http_error_handler, validation_error_handler
from app.core.middleware import (
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    setup_cors,
)
from app.db.postgres import engine
from app.db.redis import close_redis, init_redis
from app.models import Base

# OpenAPI constants
OPENAPI_BEARER_FORMAT: Final[str] = "JWT"
OPENAPI_AUTH_SCHEME: Final[str] = "bearer"
OPENAPI_AUTH_TYPE: Final[str] = "http"


@asynccontextmanager
async def register_init(_: FastAPI) -> AsyncGenerator[None]:
    """Initialize application dependencies."""
    try:
        # Initialize database
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        # Initialize Redis
        await init_redis()

        yield

    finally:
        # Cleanup
        if engine is not None:
            await engine.dispose()
        await close_redis()


def register_openapi(app: FastAPI) -> None:
    """Register OpenAPI schema and documentation."""

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )

        openapi_schema["components"]["securitySchemes"] = {
            "Bearer": {
                "type": OPENAPI_AUTH_TYPE,
                "scheme": OPENAPI_AUTH_SCHEME,
                "bearerFormat": OPENAPI_BEARER_FORMAT,
                "description": "JWT token from login or social auth",
            }
        }

        openapi_schema["security"] = [{"Bearer": []}]
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

    app.openapi = custom_openapi  # type: ignore


def register_middleware(app: FastAPI) -> None:
    """Register application middleware."""

    class APIVersionMiddleware(BaseHTTPMiddleware):
        """Middleware to add API version header."""

        async def dispatch(
            self, request: Request, call_next: RequestResponseEndpoint
        ) -> Response:
            """Add API version header to response."""
            response = await call_next(request)
            response.headers["X-API-Version"] = settings.PROJECT_VERSION
            return response

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
    )
    app.add_middleware(APIVersionMiddleware)
    setup_cors(app)


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers."""
    app.add_exception_handler(HTTPException, http_error_handler)  # type: ignore
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore


def register_routes(app: FastAPI) -> None:
    """Register application routes."""
    app.include_router(system_router)
    app.include_router(api_v1_router, prefix="/api")


def register_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        description=settings.PROJECT_DESCRIPTION,
        version=settings.PROJECT_VERSION,
        lifespan=register_init,
        docs_url=None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url=SWAGGER_OAUTH2_REDIRECT_URL,
    )

    # Register components
    register_openapi(app)
    register_middleware(app)
    register_exception_handlers(app)
    register_routes(app)

    return app
