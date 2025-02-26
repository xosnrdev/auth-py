"""Request utilities for handling client IP addresses securely."""

import ipaddress
from typing import Final

from fastapi import Request

UNKNOWN_IP: Final[str] = "unknown"
MAX_IP_LENGTH: Final[int] = 45


def is_valid_ip(ip: str) -> bool:
    """Validate if string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """Extract client IP safely from request, handling proxy scenarios."""
    assert isinstance(request, Request), "Input must be a FastAPI Request object"

    if request.client and request.client.host:
        client_ip = request.client.host
        assert len(client_ip) <= MAX_IP_LENGTH, f"Client IP exceeds maximum length of {MAX_IP_LENGTH}"
        if is_valid_ip(client_ip):
            return client_ip

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        assert len(forwarded) <= MAX_IP_LENGTH * 5, "X-Forwarded-For header exceeds maximum length"
        first_ip = forwarded.split(",")[0].strip()
        if is_valid_ip(first_ip):
            return first_ip

    return UNKNOWN_IP
