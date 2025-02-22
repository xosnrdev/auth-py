"""Request utilities for FastAPI applications."""

from fastapi import Request


def get_client_ip(request: Request) -> str:
    """Get client IP address from request.

    Args:
        request: FastAPI request object

    Returns:
        str: Client IP address
    """
    if request.client and request.client.host:
        return request.client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"
