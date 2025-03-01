"""Session middleware configuration."""

import logging

from fastapi import FastAPI
from starlette.middleware.sessions import SessionMiddleware

from app.core.config import Environment, settings

logger = logging.getLogger(__name__)


def setup_session_middleware(app: FastAPI, secret_key: str) -> None:
    """Configure session middleware for the application.

    Args:
        app: The FastAPI application instance
        secret_key: Secret key for signing session data
    """
    app.add_middleware(
        SessionMiddleware,
        secret_key=secret_key,
        session_cookie="oauth_session",
        max_age=settings.COOKIE_MAX_AGE_SECS,
        same_site="lax",
        https_only=settings.ENVIRONMENT == Environment.PRODUCTION,
        path="/api/v1/auth/social",
    )
