"""Response time middleware for measuring request processing time."""

import logging
import time
from typing import Final

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

HEADER_NAME: Final[str] = "X-Response-Time"


class ResponseTimeMiddleware(BaseHTTPMiddleware):
    """Middleware for measuring and logging request processing time."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request and measure response time.

        Args:
            request: FastAPI request
            call_next: Next middleware in chain

        Returns:
            FastAPI response
        """
        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            process_time = time.perf_counter() - start_time

            response.headers[HEADER_NAME] = f"{process_time * 1000:.2f}ms"

            logger.debug(
                "Request processed in %.2fms: %s %s",
                process_time * 1000,
                request.method,
                request.url.path,
            )

            return response

        except Exception as e:
            process_time = time.perf_counter() - start_time
            logger.error(
                "Request failed in %.2fms: %s %s - %s",
                process_time * 1000,
                request.method,
                request.url.path,
                str(e),
            )
            raise
