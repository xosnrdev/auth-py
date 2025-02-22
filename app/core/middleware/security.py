"""Security middleware implementing CSRF, CORS, and HSTS protection."""

import secrets
from collections.abc import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from app.core.config import settings


class CSRFMiddleware(BaseHTTPMiddleware):
    """CSRF protection middleware using double-submit cookie pattern.

    Implements CSRF protection by:
    1. Setting a CSRF token in a secure cookie
    2. Requiring the same token in a custom header for unsafe methods
    3. Using a cryptographically secure token
    """

    def __init__(self, app: ASGIApp, csrf_header: str = "X-CSRF-Token") -> None:
        """Initialize CSRF middleware.

        Args:
            app: ASGI application
            csrf_header: Custom header name for CSRF token
        """
        super().__init__(app)
        self.csrf_header = csrf_header
        self.safe_methods = {"GET", "HEAD", "OPTIONS"}

    def _generate_csrf_token(self) -> str:
        """Generate a secure random token.

        Returns:
            str: Random token in hex format
        """
        return secrets.token_hex(32)  # 256 bits of entropy

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Process each request through CSRF protection.

        Args:
            request: FastAPI request object
            call_next: Next middleware in chain

        Returns:
            Response: FastAPI response object

        Raises:
            HTTPException: If CSRF validation fails
        """
        if request.method in self.safe_methods:
            response = await call_next(request)
            return response

        # For unsafe methods, validate CSRF token
        cookie_token = request.cookies.get("csrf_token")
        header_token = request.headers.get(self.csrf_header)

        if not cookie_token:
            # No CSRF token yet, generate one
            cookie_token = self._generate_csrf_token()
        elif not header_token or cookie_token != header_token:
            # Token missing or mismatch
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token validation failed",
            )

        # Process request
        response = await call_next(request)

        # Ensure token is set in cookie
        response.set_cookie(
            key="csrf_token",
            value=cookie_token,
            httponly=True,
            secure=True,  # Always require HTTPS
            samesite="lax",  # Always use lax for security
        )

        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Security headers middleware implementing HSTS and other protections."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add security headers to response.

        Args:
            request: FastAPI request object
            call_next: Next middleware in chain

        Returns:
            Response: FastAPI response object with security headers
        """
        response = await call_next(request)

        # HSTS: Require HTTPS for 1 year, include subdomains
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Prevent browsers from MIME-sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Disable browser features that could be security risks
        response.headers["Permissions-Policy"] = (
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
            "magnetometer=(), microphone=(), payment=(), usb=()"
        )

        # Control browser features and APIs
        response.headers["Feature-Policy"] = (
            "microphone 'none'; geolocation 'none'; camera 'none'"
        )

        # XSS protection (although modern browsers use CSP)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        return response


def setup_cors(app: FastAPI) -> None:
    """Configure CORS middleware with secure defaults.

    Args:
        app: FastAPI application instance
    """
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
        allow_methods=settings.CORS_ALLOW_METHODS,
        allow_headers=settings.CORS_ALLOW_HEADERS,
        max_age=3600,  # Cache preflight requests for 1 hour
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
    )
