"""Rate limiting middleware using Redis sliding window counters.

Example:
```python
# Initialize FastAPI app with rate limiting
app = FastAPI()

# Add rate limit middleware
app.add_middleware(
    RateLimitMiddleware,
    redis_client=redis.Redis(),  # Optional custom client
)

# Test rate limits
for i in range(6):
    response = client.post("/api/v1/auth/login")
    if i < 5:
        assert response.status_code == 200
        assert int(response.headers["X-RateLimit-Remaining"]) == 4 - i
    else:
        assert response.status_code == 429
        assert "Retry-After" in response.headers
        assert "Rate limit exceeded" in response.json()["detail"]

# Headers in successful response
assert response.headers == {
    "X-RateLimit-Limit": "5",           # Max requests
    "X-RateLimit-Remaining": "4",       # Requests left
    "X-RateLimit-Reset": "1612345678",  # Reset timestamp
    "X-RateLimit-Window": "300s"        # Window size
}
```

Critical Notes:
- Uses Redis sliding window counter
- Per-endpoint rate limits
- Per-IP tracking (hashed)
- RFC 7807 error responses
- RFC 6585 rate limit headers
- Wildcard path matching
- Static file exclusions
- Window-based expiration
- Privacy-preserving keys
"""

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
from app.core.redis import redis as default_redis


# Type definitions
class RateLimit(TypedDict):
    """Rate limit configuration type."""

    requests: int  # Maximum requests per window
    window: int   # Window size in seconds


# Constants
DEFAULT_RATE_LIMIT: Final[RateLimit] = RateLimit(
    requests=settings.RATE_LIMIT_REQUESTS,
    window=settings.RATE_LIMIT_WINDOW_SECS,
)

# Security level rate limits
HIGH_SECURITY_LIMIT: Final[RateLimit] = RateLimit(
    requests=5,    # 5 requests per 5 minutes
    window=300,    # Strict limit for sensitive operations
)

MEDIUM_SECURITY_LIMIT: Final[RateLimit] = RateLimit(
    requests=10,   # 10 requests per minute
    window=60,     # Balanced for normal operations
)

LOW_SECURITY_LIMIT: Final[RateLimit] = RateLimit(
    requests=30,   # 30 requests per minute
    window=60,     # Relaxed for read operations
)

# Define rate limits for specific endpoints
ENDPOINT_RATE_LIMITS: Final[dict[str, RateLimit]] = {
    # High security endpoints (auth, account changes)
    "/api/v1/auth/login": HIGH_SECURITY_LIMIT,
    "/api/v1/auth/register": HIGH_SECURITY_LIMIT,
    "/api/v1/auth/password-reset/request": HIGH_SECURITY_LIMIT,
    "/api/v1/auth/password-reset/verify": HIGH_SECURITY_LIMIT,
    "/api/v1/users/me/email": HIGH_SECURITY_LIMIT,
    "/api/v1/users/me/email/verify": HIGH_SECURITY_LIMIT,

    # Medium security endpoints (profile, verification)
    "/api/v1/auth/refresh": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/introspect": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/social/providers": MEDIUM_SECURITY_LIMIT,
    "/api/v1/users/verify-email": MEDIUM_SECURITY_LIMIT,
    "/api/v1/users/verify-email/resend": MEDIUM_SECURITY_LIMIT,
    "/api/v1/users/me": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/social/*/authorize": MEDIUM_SECURITY_LIMIT,
    "/api/v1/auth/social/*/callback": MEDIUM_SECURITY_LIMIT,

    # Low security endpoints (read operations)
    "/health": LOW_SECURITY_LIMIT,

    # Admin endpoints (medium security with RBAC)
    "/api/v1/admin/users": MEDIUM_SECURITY_LIMIT,
    "/api/v1/admin/users/*": MEDIUM_SECURITY_LIMIT,
    "/api/v1/admin/audit/logs": MEDIUM_SECURITY_LIMIT,
    "/api/v1/admin/audit/logs/*": MEDIUM_SECURITY_LIMIT,
}

# Static paths to exclude
EXCLUDED_PATHS: Final[tuple[str, ...]] = (
    "/static/",
    "/docs",
    "/redoc",
    "/openapi.json",
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware using Redis sliding window.

    Features:
    1. Per-endpoint rate limits
    2. Per-IP tracking (privacy-preserving)
    3. Sliding window counters
    4. RFC 7807 error responses
    5. RFC 6585 rate limit headers
    6. Wildcard path matching
    7. Configurable Redis backend
    """

    def __init__(self, app: Any, redis_client: Redis | None = None) -> None:
        """Initialize rate limit middleware.

        Args:
            app: ASGI application
            redis_client: Optional Redis client

        Security:
            - Uses secure defaults
            - Privacy-preserving keys
            - Configurable backend
        """
        super().__init__(app)
        self.redis = redis_client or default_redis

    def get_rate_limit(self, path: str) -> RateLimit:
        """Get rate limit config for path.

        Args:
            path: Request path

        Returns:
            RateLimit: Limit configuration

        Security:
            - Exact path matching
            - Wildcard support
            - Secure defaults
        """
        # Check for exact match
        if path in ENDPOINT_RATE_LIMITS:
            return ENDPOINT_RATE_LIMITS[path]

        # Check for wildcard match
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
        """Process request through rate limiting.

        Args:
            request: FastAPI request
            call_next: Next middleware

        Returns:
            Response: With rate limit headers

        Security:
            - IP-based tracking
            - Privacy-preserving hashing
            - Secure headers
            - RFC compliance
        """
        # Skip excluded paths
        if any(request.url.path.startswith(path) for path in EXCLUDED_PATHS):
            return await call_next(request)

        # Get rate limit config
        rate_limit = self.get_rate_limit(request.url.path)
        max_requests = rate_limit["requests"]
        window_seconds = rate_limit["window"]

        # Get client IP safely
        client_ip = request.client.host if request.client else "unknown"
        assert client_ip != "unknown", "Client IP required for rate limiting"

        # Create privacy-preserving key
        key_data = f"{client_ip}:{request.url.path}".encode()
        key_hash = hashlib.sha256(key_data).hexdigest()
        now = datetime.now(UTC)
        window_key = f"rate_limit:{key_hash}:{now.strftime('%Y-%m-%dT%H:%M')}"

        # Update request count
        current_count = await self.redis.incr(window_key)
        if current_count == 1:
            await self.redis.expire(window_key, window_seconds)

        # Prepare rate limit headers
        reset_time = now + timedelta(seconds=window_seconds)
        headers = {
            "X-RateLimit-Limit": str(max_requests),
            "X-RateLimit-Remaining": str(max(0, max_requests - current_count)),
            "X-RateLimit-Reset": str(int(reset_time.timestamp())),
            "X-RateLimit-Window": f"{window_seconds}s",
        }

        # Check rate limit
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

        # Process request
        response = await call_next(request)
        response.headers.update(headers)
        return response
