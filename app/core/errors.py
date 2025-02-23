"""Error handling utilities following RFC 7807 Problem Details standard."""

from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field


class ProblemDetail(BaseModel):
    """RFC 7807 Problem Details for HTTP APIs."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "https://example.com/problems/constraint-violation",
                "title": "The request parameters failed validation",
                "status": 400,
                "detail": "Password must be at least 8 characters long",
                "instance": "/api/v1/auth/register"
            }
        }
    )

    type: str = Field(
        default="about:blank",
        description="A URI reference that identifies the problem type",
    )
    title: str = Field(
        description="A short, human-readable summary of the problem type",
    )
    status: int = Field(
        description="The HTTP status code",
    )
    detail: str = Field(
        description="A human-readable explanation specific to this occurrence of the problem",
    )
    instance: str | None = Field(
        default=None,
        description="A URI reference that identifies the specific occurrence of the problem",
    )
    errors: list[dict[str, Any]] | None = Field(
        default=None,
        description="A list of validation errors",
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Convert HTTPException to RFC 7807 Problem Details."""
    problem = ProblemDetail(
        type=f"https://httpstatuses.com/{exc.status_code}",
        title=str(exc.detail),
        status=exc.status_code,
        detail=str(exc.detail),
        instance=str(request.url),
    )

    return JSONResponse(
        status_code=exc.status_code,
        content=problem.model_dump(exclude_none=True),
        headers=exc.headers,
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Convert validation errors to RFC 7807 Problem Details."""
    problem = ProblemDetail(
        type="https://fastapi.tiangolo.com/tutorial/handling-errors/#validation-errors",
        title="Request Validation Error",
        status=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="The request parameters failed validation",
        instance=str(request.url),
        errors=list(exc.errors()),  # Convert Sequence to list
    )

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=problem.model_dump(exclude_none=True),
    )
