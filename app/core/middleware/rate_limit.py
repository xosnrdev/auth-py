"""Rate limit middleware for controlling request frequency."""

import logging

from fastapi import Request, Response
from fastapi_limiter.depends import RateLimiter
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import settings
from app.core.middleware.context import client_ip_ctx

logger = logging.getLogger(__name__)

EXCLUDED_PATHS = {
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
}


async def get_identifier(_: Request) -> str:
    """Get identifier for rate limiting.

    Args:
        request: FastAPI request

    Returns:
        String identifier for rate limiting, defaults to "unknown" if IP not found
    """
    return client_ip_ctx.get() or "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting requests."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request and apply rate limiting.

        Args:
            request: FastAPI request
            call_next: Next middleware in chain

        Returns:
            FastAPI response
        """
        if request.url.path in EXCLUDED_PATHS:
            return await call_next(request)

        try:
            rate_limiter = RateLimiter(
                times=settings.RATE_LIMIT_REQUESTS,
                seconds=settings.RATE_LIMIT_WINDOW_SECS,
                identifier=get_identifier,
            )

            response = Response()

            await rate_limiter(request, response)

            return await call_next(request)

        except Exception as e:
            logger.error("Rate limiting failed: %s", str(e), exc_info=True)
            return await call_next(request)
