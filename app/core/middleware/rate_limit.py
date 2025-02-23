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
from app.core.errors import ProblemDetail
from app.core.redis import redis as default_redis

# Define rate limits for specific endpoints
ENDPOINT_RATE_LIMITS = {
    # Auth endpoints
    "/api/v1/auth/login": {"requests": 5, "window": 300},  # 5 requests per 5 minutes
    "/api/v1/auth/register": {"requests": 3, "window": 3600},  # 3 requests per hour
    "/api/v1/auth/verify-email/resend": {"requests": 3, "window": 3600},  # 3 requests per hour
    "/api/v1/auth/refresh": {"requests": 10, "window": 600},  # 10 requests per 10 minutes

    # User management
    "/api/v1/auth/me": {"requests": 60, "window": 60},  # 60 requests per minute
    "/api/v1/auth/me/sessions": {"requests": 30, "window": 60},  # 30 requests per minute

    # Social auth
    "/api/v1/auth/social/*/authorize": {"requests": 10, "window": 300},  # 10 requests per 5 minutes
    "/api/v1/auth/social/*/callback": {"requests": 10, "window": 300},  # 10 requests per 5 minutes
}

# Default rate limit for unspecified endpoints
DEFAULT_RATE_LIMIT = {
    "requests": settings.RATE_LIMIT_REQUESTS,
    "window": settings.RATE_LIMIT_WINDOW_SECS,
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis sliding window.

    Implements per-endpoint and per-IP rate limiting using Redis.
    Supports both global and endpoint-specific rate limits.
    Returns RFC 7807 Problem Details for rate limit errors.
    """

    def __init__(self, app: Any, redis_client: Redis | None = None) -> None:
        """Initialize middleware with optional Redis client.

        Args:
            app: ASGI application
            redis_client: Optional Redis client, defaults to global client
        """
        super().__init__(app)
        self.redis = redis_client or default_redis

    def get_rate_limit(self, path: str) -> dict[str, int]:
        """Get rate limit configuration for path.

        Args:
            path: Request path

        Returns:
            dict: Rate limit configuration with requests and window
        """
        # Check for exact match
        if path in ENDPOINT_RATE_LIMITS:
            return ENDPOINT_RATE_LIMITS[path]

        # Check for wildcard match
        for pattern, limit in ENDPOINT_RATE_LIMITS.items():
            if "*" in pattern:
                # Convert pattern to regex-like matching
                pattern_parts = pattern.split("*")
                if all(part in path for part in pattern_parts):
                    return limit

        return DEFAULT_RATE_LIMIT

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
            return await call_next(request)

        # Get rate limit for endpoint
        rate_limit = self.get_rate_limit(request.url.path)
        max_requests = rate_limit["requests"]
        window_seconds = rate_limit["window"]

        # Get client IP
        client_ip = request.client.host if request.client else "unknown"

        # Create Redis key with IP and path hash for privacy
        key_data = f"{client_ip}:{request.url.path}".encode()
        key_hash = hashlib.sha256(key_data).hexdigest()
        now = datetime.now(UTC)
        window_key = f"rate_limit:{key_hash}:{now.strftime('%Y-%m-%dT%H:%M')}"

        # Increment request count
        current_count = await self.redis.incr(window_key)

        # Set expiration on new keys
        if current_count == 1:
            await self.redis.expire(window_key, window_seconds)

        # Add rate limit headers
        headers = {
            "X-RateLimit-Limit": str(max_requests),
            "X-RateLimit-Remaining": str(max(0, max_requests - current_count)),
            "X-RateLimit-Reset": str(int((now + timedelta(seconds=window_seconds)).timestamp())),
            "X-RateLimit-Window": f"{window_seconds}s",
        }

        # Check rate limit
        if current_count > max_requests:
            retry_after = window_seconds - now.second
            problem = ProblemDetail(
                type="https://tools.ietf.org/html/rfc6585#section-4",
                title="Too Many Requests",
                status=429,
                detail=(
                    f"Rate limit exceeded. "
                    f"Please wait {retry_after} seconds before retrying. "
                    f"Limit is {max_requests} requests per {window_seconds} seconds."
                ),
                instance=str(request.url),
            )
            headers["Retry-After"] = str(retry_after)
            return JSONResponse(
                status_code=429,
                content=problem.model_dump(exclude_none=True),
                headers=headers,
            )

        # Continue with request
        response = await call_next(request)

        # Add rate limit headers to response
        for key, value in headers.items():
            response.headers[key] = value

        return response
