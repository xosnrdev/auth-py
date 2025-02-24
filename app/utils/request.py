"""Request utilities for handling client IP addresses securely.

Key points:
- Extracts real client IP when behind proxies (X-Forwarded-For)
- Handles proxy chains by using first IP in chain
- Validates headers to prevent spoofing
- Returns "unknown" if IP can't be determined safely

Example:
```python
@app.get("/")
async def root(request: Request):
    client_ip = get_client_ip(request)  # "1.2.3.4" or "unknown"
    if client_ip != "unknown":
        # Use IP for rate limiting, geo-features, etc
```

Security note: If your app is behind a reverse proxy (e.g. nginx), ensure it's
configured to set X-Forwarded-For correctly.
"""

import ipaddress
from typing import Final

from fastapi import Request

# Constants for validation
UNKNOWN_IP: Final[str] = "unknown"
MAX_IP_LENGTH: Final[int] = 45  # Maximum length for IPv6 address


def is_valid_ip(ip: str) -> bool:
    """Validate if string is a valid IP address.

    Args:
        ip: String to validate

    Returns:
        True if valid IPv4 or IPv6 address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """Extract client IP safely from request, handling proxy scenarios.

    Priority:
    1. Direct client IP (request.client.host)
    2. First IP in X-Forwarded-For chain
    3. Fallback to "unknown"

    Args:
        request: FastAPI request object

    Returns:
        IP address string or "unknown"
    """
    # Assert request object validity
    assert isinstance(request, Request), "Input must be a FastAPI Request object"

    # Check direct client IP
    if request.client and request.client.host:
        client_ip = request.client.host
        assert len(client_ip) <= MAX_IP_LENGTH, f"Client IP exceeds maximum length of {MAX_IP_LENGTH}"
        if is_valid_ip(client_ip):
            return client_ip

    # Check X-Forwarded-For header
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Validate header length
        assert len(forwarded) <= MAX_IP_LENGTH * 5, "X-Forwarded-For header exceeds maximum length"

        # Get first IP in chain
        first_ip = forwarded.split(",")[0].strip()
        if is_valid_ip(first_ip):
            return first_ip

    return UNKNOWN_IP
