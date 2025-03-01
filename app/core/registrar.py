"""Registrar for FastAPI application setup."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi_limiter import FastAPILimiter

from app.api.system import router as system_router
from app.api.v1 import router as api_router
from app.core.config import Environment, settings
from app.core.database import close_redis, engine, init_redis, redis
from app.core.errors import http_error_handler, validation_error_handler
from app.core.middleware.audit import AuditMiddleware
from app.core.middleware.context import RequestContextMiddleware
from app.core.middleware.rate_limit import RateLimitMiddleware
from app.core.middleware.response_time import ResponseTimeMiddleware
from app.core.middleware.security import SecurityHeadersMiddleware, setup_cors
from app.core.middleware.session import setup_session_middleware
from app.core.middleware.version import APIVersionMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan manager for startup and shutdown events.

    Args:
        app: FastAPI application instance

    Yields:
        None
    """
    try:
        # Startup
        await init_redis()
        logger.info("Redis connection pool initialized")

        # Initialize rate limiter
        await FastAPILimiter.init(redis)
        logger.info("Rate limiter initialized")

        yield
    except Exception as e:
        logger.error("Failed to initialize services: %s", str(e))
        raise
    finally:
        # Shutdown
        try:
            await engine.dispose()
            logger.info("Database connection pool closed")
        except Exception as e:
            logger.error("Failed to close database pool: %s", str(e))

        try:
            await close_redis()
            logger.info("Redis connection pool closed")
        except Exception as e:
            logger.error("Failed to close Redis pool: %s", str(e))


def create_app() -> FastAPI:
    """Create and configure FastAPI application.

    Returns:
        Configured FastAPI application
    """
    app = FastAPI(
        title=settings.PROJECT_NAME,
        version=settings.PROJECT_VERSION,
        description=settings.PROJECT_DESCRIPTION,
        docs_url="/docs" if settings.ENVIRONMENT != Environment.PRODUCTION else None,
        redoc_url="/redoc" if settings.ENVIRONMENT != Environment.PRODUCTION else None,
        openapi_url="/openapi.json"
        if settings.ENVIRONMENT != Environment.PRODUCTION
        else None,
        swagger_ui_oauth2_redirect_url="/docs/oauth2-redirect",
        lifespan=lifespan,
    )

    register_exception_handlers(app)
    register_routers(app)
    register_middleware(app)

    return app


def register_middleware(app: FastAPI) -> None:
    """Register middleware.

    Args:
        app: FastAPI application

    Note:
        Middleware is applied in reverse order, so the first middleware registered
        will be the last to run, and the last middleware registered will be the
        first to run.

        Order of execution (first to last):
        1. CORS (cross-origin)
        2. Session (auth)
        3. Context (request context)
        4. Security Headers (security)
        5. Response Time (timing)
        6. Version (headers)
        7. Rate Limit (throttling)
        8. Audit (logging)
    """
    app.add_middleware(AuditMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(APIVersionMiddleware)
    app.add_middleware(ResponseTimeMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    setup_session_middleware(app, settings.JWT_SECRET.get_secret_value())
    setup_cors(app)


def register_routers(app: FastAPI) -> None:
    """Register API routers.

    Args:
        app: FastAPI application
    """
    app.include_router(system_router)
    app.include_router(api_router, prefix="/api")


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers.

    Args:
        app: FastAPI application
    """
    app.add_exception_handler(HTTPException, http_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]
