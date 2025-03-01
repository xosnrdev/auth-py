"""HTTP error handling following RFC 7807 Problem Details."""

from http import HTTPStatus
from typing import Any, Final

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

DEFAULT_ERROR_TYPE: Final[str] = "about:blank"
VALIDATION_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7807:validation"
AUTH_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7807:auth"
RATE_LIMIT_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:6585:status:429"
RESOURCE_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7231:status:404"
SERVER_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7231:status:500"

MAX_INSTANCE_LENGTH: Final[int] = 255

ERROR_CODES: Final[dict[int, str]] = {
    status.HTTP_401_UNAUTHORIZED: "AUTH001",
    status.HTTP_403_FORBIDDEN: "AUTH002",
    status.HTTP_404_NOT_FOUND: "RESOURCE001",
    status.HTTP_400_BAD_REQUEST: "VALIDATION001",
    status.HTTP_422_UNPROCESSABLE_ENTITY: "VALIDATION002",
    status.HTTP_429_TOO_MANY_REQUESTS: "RATE001",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "SERVER001",
    status.HTTP_503_SERVICE_UNAVAILABLE: "SERVER002",
}

ERROR_TYPES: Final[dict[str, str]] = {
    "AUTH": AUTH_ERROR_TYPE,
    "RESOURCE": RESOURCE_ERROR_TYPE,
    "VALIDATION": VALIDATION_ERROR_TYPE,
    "RATE": RATE_LIMIT_ERROR_TYPE,
    "SERVER": SERVER_ERROR_TYPE,
}

JSON_CONTENT_TYPE: Final[str] = "application/problem+json"

CACHE_CONTROL: Final[str] = "no-store, no-cache, must-revalidate"

HTTP_STATUS_TITLES: Final[dict[int, str]] = {
    status.HTTP_400_BAD_REQUEST: "Bad Request",
    status.HTTP_401_UNAUTHORIZED: "Unauthorized",
    status.HTTP_403_FORBIDDEN: "Forbidden",
    status.HTTP_404_NOT_FOUND: "Not Found",
    status.HTTP_405_METHOD_NOT_ALLOWED: "Method Not Allowed",
    status.HTTP_406_NOT_ACCEPTABLE: "Not Acceptable",
    status.HTTP_409_CONFLICT: "Conflict",
    status.HTTP_422_UNPROCESSABLE_ENTITY: "Unprocessable Entity",
    status.HTTP_429_TOO_MANY_REQUESTS: "Too Many Requests",
    status.HTTP_500_INTERNAL_SERVER_ERROR: "Internal Server Error",
    status.HTTP_501_NOT_IMPLEMENTED: "Not Implemented",
    status.HTTP_502_BAD_GATEWAY: "Bad Gateway",
    status.HTTP_503_SERVICE_UNAVAILABLE: "Service Unavailable",
    status.HTTP_504_GATEWAY_TIMEOUT: "Gateway Timeout",
}


class ProblemDetail(BaseModel):
    """RFC 7807 Problem Details for HTTP APIs."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "type": "validation_error",
                    "title": "Validation Error",
                    "status": 422,
                    "detail": "Password too short",
                    "instance": "/api/v1/auth/register",
                    "errors": [
                        {
                            "loc": ["body", "password"],
                            "msg": "min length 8",
                            "type": "value_error",
                        }
                    ],
                }
            ]
        }
    )

    type: str = Field(default=DEFAULT_ERROR_TYPE)
    title: str
    status: int
    detail: str
    instance: str = Field(max_length=MAX_INSTANCE_LENGTH)
    code: str | None = None
    errors: list[dict[str, Any]] | None = None


def truncate_url(url: str, max_length: int = MAX_INSTANCE_LENGTH) -> str:
    """Truncate URL to max length while preserving the path.

    Args:
        url: URL to truncate
        max_length: Maximum length allowed

    Returns:
        Truncated URL with path preserved
    """
    if len(url) <= max_length:
        return url

    path = url.split("?")[0]
    if len(path) > max_length:
        return path[:max_length-3] + "..."
    return path


async def http_error_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions by converting to RFC 7807 problem details."""
    error_type = ERROR_TYPES.get(
        ERROR_CODES.get(exc.status_code, "").split("0")[0],
        DEFAULT_ERROR_TYPE,
    )

    problem = ProblemDetail(
        type=error_type,
        title=HTTPStatus(exc.status_code).phrase,
        status=exc.status_code,
        detail=str(exc.detail),
        instance=truncate_url(str(request.url)),
        code=ERROR_CODES.get(exc.status_code),
    )

    headers = {
        "Content-Type": JSON_CONTENT_TYPE,
        "Cache-Control": CACHE_CONTROL,
    }
    if exc.headers:
        headers.update(exc.headers)

    return JSONResponse(
        status_code=exc.status_code,
        content=problem.model_dump(exclude_none=True),
        headers=headers,
    )


async def validation_error_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Handle validation errors by converting to RFC 7807 problem details."""
    problem = ProblemDetail(
        type=VALIDATION_ERROR_TYPE,
        title="Validation Error",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Request validation failed",
        instance=truncate_url(str(request.url)),
        code=ERROR_CODES[status.HTTP_422_UNPROCESSABLE_ENTITY],
        errors=[
            {
                "loc": err["loc"],
                "msg": err["msg"],
                "type": err["type"],
            }
            for err in exc.errors()
        ],
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem.model_dump(exclude_none=True),
        headers={
            "Content-Type": JSON_CONTENT_TYPE,
            "Cache-Control": CACHE_CONTROL,
        },
    )


class AppError(Exception):
    """Base error class for application errors."""

    def __init__(self, message: str, details: Any = None) -> None:
        """Initialize error with message and optional details.

        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.details = details


class RepositoryError(AppError):
    """Base error class for repository layer errors."""


class DatabaseError(RepositoryError):
    """Error raised when a database operation fails."""


class DuplicateError(DatabaseError):
    """Error raised when a unique constraint is violated."""


class NotFoundError(RepositoryError):
    """Error raised when a requested resource is not found."""
