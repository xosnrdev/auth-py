"""API version middleware for handling version headers and deprecation."""

import logging
from collections.abc import Awaitable, Callable
from typing import Final

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

logger = logging.getLogger(__name__)

API_VERSION_HEADER: Final[str] = "X-API-Version"


class APIVersionMiddleware(BaseHTTPMiddleware):
    """Middleware for handling API version headers and deprecation notices."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Add API version headers to each response.

        Args:
            request: The incoming request
            call_next: The next middleware/route handler

        Returns:
            The response with API version headers
        """
        response = await call_next(request)
        response.headers[API_VERSION_HEADER] = settings.PROJECT_VERSION

        return response
