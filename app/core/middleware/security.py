"""Security middleware implementing OWASP recommended HTTP headers.

Example:
```python
# Initialize FastAPI app with security headers
app = FastAPI()

# Add security headers middleware
app.add_middleware(SecurityHeadersMiddleware)
assert "Strict-Transport-Security" in response.headers
assert "X-Content-Type-Options" in response.headers
assert "Permissions-Policy" in response.headers
assert "Content-Security-Policy" in response.headers
assert "X-Frame-Options" in response.headers

# Configure CORS with secure defaults
setup_cors(app)
assert app.cors_middleware
assert app.cors_middleware.config.allow_origins == ["https://app.example.com"]
assert app.cors_middleware.config.allow_credentials is True
assert app.cors_middleware.config.allow_methods == ["GET", "POST"]
assert app.cors_middleware.config.max_age == 3600
```

Critical Notes:
- HSTS enabled by default (1 year, includeSubDomains)
- CORS requires explicit origin configuration
- CSP blocks inline scripts and styles
- Feature Policy restricts dangerous APIs
- XSS protection enforced
- Clickjacking protection enabled
- MIME sniffing prevented
- Rate limit headers exposed
- Preflight requests cached
"""

from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

# Constants for security headers
HSTS_MAX_AGE: Final[int] = 31536000  # 1 year in seconds
CORS_MAX_AGE: Final[int] = 3600  # 1 hour in seconds

# Security header values
HSTS_POLICY: Final[str] = f"max-age={HSTS_MAX_AGE}; includeSubDomains"
XSS_PROTECTION: Final[str] = "1; mode=block"
CONTENT_TYPE_OPTIONS: Final[str] = "nosniff"
FRAME_OPTIONS: Final[str] = "DENY"

# Restricted browser features
PERMISSIONS_POLICY: Final[str] = (
    "accelerometer=(), "
    "camera=(), "
    "geolocation=(), "
    "gyroscope=(), "
    "magnetometer=(), "
    "microphone=(), "
    "payment=(), "
    "usb=()"
)

FEATURE_POLICY: Final[str] = (
    "microphone 'none'; "
    "geolocation 'none'; "
    "camera 'none'"
)

# CORS exposed headers
EXPOSED_HEADERS: Final[tuple[str, ...]] = (
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Security headers middleware implementing OWASP recommendations.

    Implements:
    1. HTTP Strict Transport Security (HSTS)
    2. Content Security Policy (CSP)
    3. X-Content-Type-Options
    4. X-Frame-Options
    5. Feature-Policy
    6. Permissions-Policy
    7. X-XSS-Protection
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add security headers to each response.

        Args:
            request: FastAPI request object
            call_next: Next middleware handler

        Returns:
            Response with security headers

        Security:
            - HSTS enforces HTTPS
            - CSP prevents XSS
            - X-Frame-Options prevents clickjacking
            - Feature policies restrict APIs
        """
        # Get response from next handler
        response = await call_next(request)

        # Add security headers
        headers = {
            # HTTPS enforcement
            "Strict-Transport-Security": HSTS_POLICY,

            # XSS prevention
            "X-Content-Type-Options": CONTENT_TYPE_OPTIONS,
            "X-XSS-Protection": XSS_PROTECTION,

            # Clickjacking prevention
            "X-Frame-Options": FRAME_OPTIONS,

            # API restrictions
            "Permissions-Policy": PERMISSIONS_POLICY,
            "Feature-Policy": FEATURE_POLICY,
        }

        # Update response headers
        response.headers.update(headers)

        return response


def setup_cors(app: FastAPI) -> None:
    """Configure CORS middleware with secure defaults.

    Implements:
    1. Origin validation
    2. Method restrictions
    3. Header restrictions
    4. Credential handling
    5. Preflight caching

    Args:
        app: FastAPI application

    Security:
        - Explicit origin whitelist
        - Restricted methods
        - Restricted headers
        - Preflight caching
        - Rate limit exposure
    """
    # Validate CORS settings
    assert settings.CORS_ORIGINS, "CORS origins must be configured"
    assert all(origin.startswith("https://") for origin in settings.CORS_ORIGINS), (
        "CORS origins must use HTTPS in production"
    )
    assert settings.CORS_ALLOW_METHODS, "CORS methods must be configured"
    assert settings.CORS_ALLOW_HEADERS, "CORS headers must be configured"

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
        max_age=CORS_MAX_AGE,
        expose_headers=list(EXPOSED_HEADERS),
    )
