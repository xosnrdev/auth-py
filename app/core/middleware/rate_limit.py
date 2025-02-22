"""Rate limiting middleware using Redis sliding window."""

import hashlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.redis import redis as default_redis


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis sliding window.

    Implements a per-IP rate limit using Redis for distributed rate limiting.
    Default configuration:
    - {settings.RATE_LIMIT_REQUESTS} requests per IP
    - {settings.RATE_LIMIT_WINDOW_SECS} seconds window
    """

    def __init__(self, app: Any, redis_client: Redis | None = None) -> None:
        """Initialize middleware with optional Redis client.

        Args:
            app: ASGI application
            redis_client: Optional Redis client, defaults to global client
        """
        super().__init__(app)
        self.redis = redis_client or default_redis
        self.max_requests = settings.RATE_LIMIT_REQUESTS
        self.window_seconds = settings.RATE_LIMIT_WINDOW_SECS

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process each request through rate limiting.

        Args:
            request: FastAPI request object
            call_next: Next middleware in chain

        Returns:
            Response: FastAPI response object
        """
        # Skip rate limiting for static files and docs
        if request.url.path.startswith(("/static/", "/docs", "/redoc", "/openapi.json")):
            response: Response = await call_next(request)
            return response

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Create Redis key with IP hash for privacy
        ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()
        now = datetime.now(UTC)
        window_key = f"rate_limit:{ip_hash}:{now.strftime('%Y-%m-%dT%H:%M')}"

        # Increment request count
        current_count = await self.redis.incr(window_key)

        # Set expiration on new keys
        if current_count == 1:
            await self.redis.expire(window_key, self.window_seconds)

        # Check rate limit
        if current_count > self.max_requests:
            retry_after = self.window_seconds - now.second
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please try again later.",
                    "retry_after": f"{retry_after} seconds",
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self.max_requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int((now + timedelta(minutes=1)).timestamp())),
                },
            )

        # Add rate limit headers
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, self.max_requests - current_count))
        response.headers["X-RateLimit-Reset"] = str(int((now + timedelta(minutes=1)).timestamp()))

        return response
