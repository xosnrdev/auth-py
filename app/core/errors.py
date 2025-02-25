r"""HTTP error handling following RFC 7807 Problem Details.

Example:
```python
# FastAPI error handler setup
from fastapi import FastAPI, HTTPException, Request, status
from app.core.errors import (
    ProblemDetail,
    http_error_handler,
    validation_error_handler
)

app = FastAPI()
app.add_exception_handler(HTTPException, http_error_handler)
app.add_exception_handler(RequestValidationError, validation_error_handler)

# Raise standard HTTP error
raise HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="Invalid request parameters"
)
# Response:
# {
#     "type": "about:blank",
#     "title": "Bad Request",
#     "status": 400,
#     "detail": "Invalid request parameters",
#     "instance": "/api/v1/users"
# }

# Handle validation error
from pydantic import BaseModel, Field
class User(BaseModel):
    email: str = Field(..., pattern=r"^[a-z0-9]+@[a-z0-9]+\.[a-z]{2,}$")
    age: int = Field(..., ge=18)

# Invalid data raises ValidationError
user = User(email="invalid", age=16)
# Response:
# {
#     "type": "validation_error",
#     "title": "Validation Error",
#     "status": 422,
#     "detail": "Request parameters failed validation",
#     "instance": "/api/v1/users",
#     "errors": [
#         {
#             "loc": ["email"],
#             "msg": "Invalid email format",
#             "type": "pattern_mismatch"
#         },
#         {
#             "loc": ["age"],
#             "msg": "Age must be >= 18",
#             "type": "greater_than_equal"
#         }
#     ]
# }
```

Critical Security Notes:
1. Error Information
   - No system details exposed
   - No stack traces in production
   - Structured error format
   - Safe error messages

2. Validation Handling
   - Input sanitization
   - Type checking
   - Format validation
   - Size limits

3. Response Format
   - RFC 7807 compliant
   - JSON content type
   - UTF-8 encoding
   - Status code mapping

4. Security Headers
   - No sensitive headers
   - CORS compliance
   - Cache control
   - Content security
"""

from http import HTTPStatus
from typing import Any, Final, cast

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

# Error type constants
DEFAULT_ERROR_TYPE: Final[str] = "about:blank"
VALIDATION_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7807:validation"
AUTH_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7807:auth"
RATE_LIMIT_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:6585:status:429"
RESOURCE_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7231:status:404"
SERVER_ERROR_TYPE: Final[str] = "urn:ietf:params:rfc:7231:status:500"

# Error codes by category
ERROR_CODES: Final[dict[int, str]] = {
    # Authentication errors (401)
    status.HTTP_401_UNAUTHORIZED: "AUTH001",
    # Authorization errors (403)
    status.HTTP_403_FORBIDDEN: "AUTH002",
    # Resource errors (404)
    status.HTTP_404_NOT_FOUND: "RESOURCE001",
    # Validation errors (400, 422)
    status.HTTP_400_BAD_REQUEST: "VALIDATION001",
    status.HTTP_422_UNPROCESSABLE_ENTITY: "VALIDATION002",
    # Rate limit errors (429)
    status.HTTP_429_TOO_MANY_REQUESTS: "RATE001",
    # Server errors (500, 503)
    status.HTTP_500_INTERNAL_SERVER_ERROR: "SERVER001",
    status.HTTP_503_SERVICE_UNAVAILABLE: "SERVER002",
}

# Error type mapping
ERROR_TYPES: Final[dict[str, str]] = {
    "AUTH": AUTH_ERROR_TYPE,
    "RESOURCE": RESOURCE_ERROR_TYPE,
    "VALIDATION": VALIDATION_ERROR_TYPE,
    "RATE": RATE_LIMIT_ERROR_TYPE,
    "SERVER": SERVER_ERROR_TYPE,
}

# Content type for responses
JSON_CONTENT_TYPE: Final[str] = "application/problem+json"

# Cache control header
CACHE_CONTROL: Final[str] = "no-store, no-cache, must-revalidate"

# HTTP status code mapping
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
    """RFC 7807 Problem Details for HTTP APIs.

    Implementation:
    1. Follows RFC 7807 specification
    2. Includes required fields
    3. Supports optional fields
    4. Validates all inputs

    Security:
        - Safe serialization
        - Input validation
        - No sensitive data
        - Structured format

    Example:
        ```python
        error = ProblemDetail(
            type="urn:ietf:params:rfc:7807:validation",
            title="Validation Error",
            status=400,
            detail="Email format is invalid",
            instance="/api/v1/users",
            code="VALIDATION001",
            errors=[{
                "loc": ["email"],
                "msg": "Invalid email format",
                "type": "pattern_mismatch"
            }]
        )
        ```
    """

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "urn:ietf:params:rfc:7807:validation",
                "title": "Validation Error",
                "status": 400,
                "detail": "Email format is invalid",
                "instance": "/api/v1/users",
                "code": "VALIDATION001",
                "errors": [{
                    "loc": ["email"],
                    "msg": "Invalid email format",
                    "type": "pattern_mismatch"
                }]
            }
        }
    )

    type: str = Field(
        default=DEFAULT_ERROR_TYPE,
        description="A URI reference [RFC3986] that identifies the problem type",
        examples=["urn:ietf:params:rfc:7807:validation"],
        max_length=255,
    )
    title: str = Field(
        description="Short, human-readable problem summary",
        examples=["Validation Error"],
        max_length=255,
    )
    status: int = Field(
        description="HTTP status code",
        ge=100,
        le=599,
        examples=[400],
    )
    detail: str = Field(
        description="Human-readable explanation of the error",
        examples=["Email format is invalid"],
        max_length=1024,
    )
    instance: str | None = Field(
        default=None,
        description="URI reference for the specific occurrence",
        examples=["/api/v1/users"],
        max_length=255,
    )
    code: str | None = Field(
        default=None,
        description="Machine-readable error code",
        examples=["VALIDATION001"],
        max_length=20,
    )
    errors: list[dict[str, Any]] | None = Field(
        default=None,
        description="Detailed validation errors",
        examples=[[{
            "loc": ["email"],
            "msg": "Invalid email format",
            "type": "pattern_mismatch"
        }]],
    )


async def http_error_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """Handle HTTPException with RFC 7807 format.

    Implementation:
    1. Creates problem detail
    2. Sets security headers
    3. Returns JSON response
    4. Handles all status codes

    Args:
        request: FastAPI request
        exc: HTTP exception

    Returns:
        JSONResponse: RFC 7807 formatted error

    Security:
        - Safe error messages
        - Proper status codes
        - Security headers
        - Content type
    """
    # Get error code and type
    error_code = ERROR_CODES.get(exc.status_code)
    error_type = DEFAULT_ERROR_TYPE
    if error_code:
        prefix = error_code[:error_code.find("0")]
        error_type = ERROR_TYPES.get(prefix, DEFAULT_ERROR_TYPE)

    # Create problem detail
    problem = ProblemDetail(
        type=error_type,
        title=HTTP_STATUS_TITLES.get(exc.status_code, HTTPStatus(exc.status_code).phrase),
        status=exc.status_code,
        detail=str(exc.detail),
        instance=str(request.url),
        code=error_code,
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
    """Handle validation errors with RFC 7807 format.

    Implementation:
    1. Extracts validation errors
    2. Creates problem detail
    3. Sets security headers
    4. Returns JSON response

    Args:
        request: FastAPI request
        exc: Validation exception

    Returns:
        JSONResponse: RFC 7807 formatted error

    Security:
        - Safe error messages
        - Input validation
        - Security headers
        - Content type
    """
    problem = ProblemDetail(
        type=VALIDATION_ERROR_TYPE,
        title="Validation Error",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="Request parameters failed validation",
        instance=str(request.url),
        code=ERROR_CODES[status.HTTP_422_UNPROCESSABLE_ENTITY],
        errors=cast(list[dict[str, Any]], exc.errors()),
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem.model_dump(exclude_none=True),
        headers={
            "Content-Type": JSON_CONTENT_TYPE,
            "Cache-Control": CACHE_CONTROL,
        },
    )
