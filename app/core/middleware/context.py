"""Request context middleware for managing request-scoped data."""

import logging
from contextvars import ContextVar
from typing import Final
from uuid import UUID, uuid4

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

logger = logging.getLogger(__name__)

request_id_ctx: ContextVar[UUID] = ContextVar("request_id")
client_ip_ctx: ContextVar[str] = ContextVar("client_ip", default="unknown")
user_agent_ctx: ContextVar[str] = ContextVar("user_agent", default="unknown")

REQUEST_ID_HEADER: Final[str] = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware for managing request context data."""

    def __init__(self, app: FastAPI) -> None:
        """Initialize middleware.

        Args:
            app: FastAPI application
        """
        super().__init__(app)
        request_id_ctx.set(uuid4())

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request and set context variables.

        Args:
            request: FastAPI request
            call_next: Next middleware in chain

        Returns:
            FastAPI response
        """
        # Generate or get request ID
        request_id_str = request.headers.get(REQUEST_ID_HEADER)
        request_id: UUID
        if request_id_str:
            try:
                request_id = UUID(request_id_str)
            except ValueError:
                request_id = uuid4()
        else:
            request_id = uuid4()

        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")

        request_id_ctx.set(request_id)
        client_ip_ctx.set(client_ip)
        user_agent_ctx.set(user_agent)

        response = await call_next(request)

        response.headers[REQUEST_ID_HEADER] = request_id.hex

        return response
