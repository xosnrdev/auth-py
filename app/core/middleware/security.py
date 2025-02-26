"""Security middleware implementing OWASP recommended HTTP headers."""

from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

HSTS_MAX_AGE: Final[int] = 31536000
CORS_MAX_AGE: Final[int] = 3600

HSTS_POLICY: Final[str] = f"max-age={HSTS_MAX_AGE}; includeSubDomains"
XSS_PROTECTION: Final[str] = "1; mode=block"
CONTENT_TYPE_OPTIONS: Final[str] = "nosniff"
FRAME_OPTIONS: Final[str] = "DENY"

CSP_POLICY: Final[str] = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "frame-src 'none'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'; "
    "upgrade-insecure-requests; "
    "block-all-mixed-content"
)

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
    """Security headers middleware implementing OWASP recommendations."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add security headers to each response."""
        response = await call_next(request)

        headers = {
            "Strict-Transport-Security": HSTS_POLICY,

            # XSS prevention
            "Content-Security-Policy": CSP_POLICY,
            "X-Content-Type-Options": CONTENT_TYPE_OPTIONS,
            "X-XSS-Protection": XSS_PROTECTION,

            # Clickjacking prevention
            "X-Frame-Options": FRAME_OPTIONS,

            # API restrictions
            "Permissions-Policy": PERMISSIONS_POLICY,
            "Feature-Policy": FEATURE_POLICY,
        }

        response.headers.update(headers)

        return response


def setup_cors(app: FastAPI) -> None:
    """Configure CORS middleware with secure defaults."""
    assert settings.CORS_ORIGINS, "CORS origins must be configured"
    assert all(origin.startswith("https://") for origin in settings.CORS_ORIGINS), (
        "CORS origins must use HTTPS in production"
    )
    assert settings.CORS_ALLOW_METHODS, "CORS methods must be configured"
    assert settings.CORS_ALLOW_HEADERS, "CORS headers must be configured"

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
        max_age=CORS_MAX_AGE,
        expose_headers=list(EXPOSED_HEADERS),
    )
