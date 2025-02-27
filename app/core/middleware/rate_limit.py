"""Rate limiting middleware using Redis sliding window counters."""

import hashlib
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final, TypedDict

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.errors import ProblemDetail
from app.db.redis import redis as default_redis


class RateLimit(TypedDict):
    """Rate limit configuration type."""

    requests: int
    window: int


DEFAULT_RATE_LIMIT: Final[RateLimit] = RateLimit(
    requests=settings.RATE_LIMIT_REQUESTS,
    window=settings.RATE_LIMIT_WINDOW_SECS,
)

HIGH_SECURITY_LIMIT: Final[RateLimit] = RateLimit(
    requests=5,
    window=300,
)

MEDIUM_SECURITY_LIMIT: Final[RateLimit] = RateLimit(
    requests=10,
    window=60,
)

LOW_SECURITY_LIMIT: Final[RateLimit] = RateLimit(
    requests=30,
    window=60,
)

ENDPOINT_RATE_LIMITS: Final[dict[str, RateLimit]] = {
    "/api/v1/auth/login": HIGH_SECURITY_LIMIT,
    "/api/v1/auth/register": HIGH_SECURITY_LIMIT,
    "/api/v1/auth/password-reset/request": HIGH_SECURITY_LIMIT,
    "/api/v1/auth/password-reset/verify": HIGH_SECURITY_LIMIT,
    "/api/v1/users/me/email": HIGH_SECURITY_LIMIT,
    "/api/v1/users/me/email/verify": HIGH_SECURITY_LIMIT,

    "/api/v1/auth/refresh": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/introspect": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/social/providers": MEDIUM_SECURITY_LIMIT,
    "/api/v1/users/verify-email": MEDIUM_SECURITY_LIMIT,
    "/api/v1/users/verify-email/resend": MEDIUM_SECURITY_LIMIT,
    "/api/v1/users/me": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/social/*/authorize": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/social/*/callback": MEDIUM_SECURITY_LIMIT,

    "/health": LOW_SECURITY_LIMIT,

    "/api/v1/admin/users": MEDIUM_SECURITY_LIMIT,
    "/api/v1/admin/users/*": MEDIUM_SECURITY_LIMIT,
    "/api/v1/admin/audit/logs": MEDIUM_SECURITY_LIMIT,
    "/api/v1/admin/audit/logs/*": MEDIUM_SECURITY_LIMIT,
}


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis sliding window."""

    def __init__(
        self,
        app: Any,
        redis_client: Redis | None = None,
        exclude_paths: set[str] | None = None,
    ) -> None:
        """Initialize rate limit middleware."""
        super().__init__(app)
        self.redis = redis_client or default_redis
        self.exclude_paths = exclude_paths or set()

    def get_rate_limit(self, path: str) -> RateLimit:
        """Get rate limit config for path."""
        if path in ENDPOINT_RATE_LIMITS:
            return ENDPOINT_RATE_LIMITS[path]

        for pattern, limit in ENDPOINT_RATE_LIMITS.items():
            if "*" in pattern:
                pattern_parts = pattern.split("*")
                if all(part in path for part in pattern_parts):
                    return limit

        return DEFAULT_RATE_LIMIT

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process request through rate limiting."""
        if request.url.path in self.exclude_paths:
            return await call_next(request)

        rate_limit = self.get_rate_limit(request.url.path)
        max_requests = rate_limit["requests"]
        window_seconds = rate_limit["window"]

        client_ip = request.client.host if request.client else "unknown"
        assert client_ip != "unknown", "Client IP required for rate limiting"

        key_data = f"{client_ip}:{request.url.path}".encode()
        key_hash = hashlib.sha256(key_data).hexdigest()
        now = datetime.now(UTC)
        window_key = f"rate_limit:{key_hash}:{now.strftime('%Y-%m-%dT%H:%M')}"

        current_count = await self.redis.incr(window_key)
        if current_count == 1:
            await self.redis.expire(window_key, window_seconds)

        reset_time = now + timedelta(seconds=window_seconds)
        headers = {
            "X-RateLimit-Limit": str(max_requests),
            "X-RateLimit-Remaining": str(max(0, max_requests - current_count)),
            "X-RateLimit-Reset": str(int(reset_time.timestamp())),
            "X-RateLimit-Window": f"{window_seconds}s",
        }

        if current_count > max_requests:
            retry_after = window_seconds - now.second
            problem = ProblemDetail(
                type="urn:ietf:params:rfc:6585:status:429",
                title="Too Many Requests",
                status=429,
                detail=(
                    f"Rate limit exceeded. "
                    f"Please wait {retry_after} seconds before retrying. "
                    f"Limit is {max_requests} requests per {window_seconds} seconds."
                ),
                instance=str(request.url),
                code="RATE001",
            )
            headers["Retry-After"] = str(retry_after)
            return JSONResponse(
                status_code=429,
                content=problem.model_dump(exclude_none=True),
                headers=headers,
            )

        response = await call_next(request)
        response.headers.update(headers)
        return response
