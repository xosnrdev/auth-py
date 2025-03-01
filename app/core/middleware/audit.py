"""Audit middleware for logging request and response details."""

import json
import logging
from datetime import UTC, datetime
from typing import Any, Protocol
from uuid import uuid4

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.middleware.context import client_ip_ctx, request_id_ctx, user_agent_ctx

logger = logging.getLogger(__name__)


class AuditLogProtocol(Protocol):
    """Protocol for audit logging."""

    async def create(self, data: dict[str, Any]) -> Any:
        """Create audit log entry.

        Args:
            data: Audit log data

        Returns:
            Created audit log entry
        """
        ...


class AuditMiddleware(BaseHTTPMiddleware):
    """Middleware for auditing requests and responses."""

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        """Process request and log audit details.

        Args:
            request: FastAPI request
            call_next: Next middleware in chain

        Returns:
            FastAPI response
        """
        # Get context data with fallbacks
        try:
            request_id = request_id_ctx.get()
        except LookupError:
            request_id = uuid4()
            logger.warning("Request ID context not found, using generated ID")

        try:
            client_ip = client_ip_ctx.get()
        except LookupError:
            client_ip = request.client.host if request.client else "unknown"
            logger.warning("Client IP context not found, using request client IP")

        try:
            user_agent = user_agent_ctx.get()
        except LookupError:
            user_agent = request.headers.get("user-agent", "unknown")
            logger.warning("User agent context not found, using request header")

        # Get request details
        method = request.method
        path = request.url.path
        query = dict(request.query_params)
        headers = dict(request.headers)

        # Remove sensitive data
        if "authorization" in headers:
            headers["authorization"] = "[REDACTED]"
        if "cookie" in headers:
            headers["cookie"] = "[REDACTED]"

        # Get request body if available
        body: dict[str, Any] = {}
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                body = await request.json()
                if "password" in body:
                    body["password"] = "[REDACTED]"
            except Exception:
                pass

        # Record start time
        start_time = datetime.now(UTC)

        try:
            # Process request
            response = await call_next(request)

            # Get response details
            status_code = response.status_code
            response_headers = dict(response.headers)

            # Log audit entry
            audit_data = {
                "request_id": request_id.hex,
                "timestamp": start_time.isoformat(),
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "query": query,
                "headers": headers,
                "body": body,
                "status_code": status_code,
                "response_headers": response_headers,
            }

            # Get audit repository from request state if available
            audit_repo = (
                request.state.audit_repo
                if hasattr(request.state, "audit_repo")
                else None
            )

            if audit_repo is not None and hasattr(audit_repo, "create"):
                await audit_repo.create(
                    {
                        "action": f"{method} {path}",
                        "details": json.dumps(audit_data),
                        "ip_address": client_ip,
                        "user_agent": user_agent,
                    }
                )
            else:
                logger.debug("Audit log: %s", json.dumps(audit_data))

            return response

        except Exception as e:
            audit_data = {
                "request_id": request_id.hex,
                "timestamp": start_time.isoformat(),
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "query": query,
                "headers": headers,
                "body": body,
                "error": str(e),
            }

            logger.error("Request failed: %s", json.dumps(audit_data))
            raise
