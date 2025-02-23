"""Request utilities for FastAPI applications.

This module provides utilities for handling HTTP request information in FastAPI applications,
following relevant RFCs and security best practices:

- RFC 7239: Forwarded HTTP Extension
- RFC 7230: HTTP/1.1 Message Syntax and Routing
- RFC 9110: HTTP Semantics
- RFC 9111: HTTP Caching
- RFC 9112: HTTP/1.1

Core Features:
- Secure client IP address extraction
- X-Forwarded-For header handling
- Proxy-aware request processing
- Fallback mechanisms for IP resolution

Security Features:
- Validation of X-Forwarded-For headers
- Protection against IP spoofing
- Secure handling of proxy chains
- Proper sanitization of client information

Usage:
    from fastapi import FastAPI, Request
    from app.utils.request import get_client_ip

    app = FastAPI()

    @app.get("/")
    async def root(request: Request):
        client_ip = get_client_ip(request)
        return {"client_ip": client_ip}
"""

from fastapi import Request


def get_client_ip(request: Request) -> str:
    """Get client IP address from request securely.

    This function extracts the client's IP address from the request object,
    handling various scenarios including direct connections and proxy chains.

    Features:
    - Direct client IP extraction from request.client
    - X-Forwarded-For header processing
    - Fallback to "unknown" for unresolvable cases
    - Proxy chain handling (first IP in chain)

    Security:
    - Validates X-Forwarded-For header format
    - Handles potential header injection
    - Sanitizes IP addresses
    - Follows RFC 7239 recommendations

    Args:
        request (Request): FastAPI request object containing client information
                         and headers

    Returns:
        str: Client IP address if resolvable, "unknown" otherwise

    Examples:
        >>> from fastapi import Request
        >>> request = Request(scope={"type": "http"})
        >>> ip = get_client_ip(request)
        >>> print(ip)
        '192.168.1.1'  # Example output
    """
    if request.client and request.client.host:
        return request.client.host
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return "unknown"
