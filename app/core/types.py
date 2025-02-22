"""Type stubs for external libraries."""

from typing import Any


# Type stubs for bcrypt
def gensalt(rounds: int = 12) -> bytes:
    """Generate a salt for password hashing."""
    raise NotImplementedError

def hashpw(password: bytes, salt: bytes) -> bytes:
    """Hash a password with a salt."""
    raise NotImplementedError

def checkpw(password: bytes, hashed: bytes) -> bool:
    """Check if a password matches a hash."""
    raise NotImplementedError

# Type stubs for jwt
def encode(payload: dict[str, Any], key: str, algorithm: str = "RS256") -> str:
    """Encode a payload into a JWT using asymmetric algorithms as per RFC 9068."""
    raise NotImplementedError

def decode(
    jwt: str,
    key: str,
    algorithms: list[str] | None = None,
    audience: str | list[str] | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Decode a JWT into a payload."""
    raise NotImplementedError

class InvalidTokenError(Exception):
    """Base class for JWT token errors."""

class ExpiredSignatureError(InvalidTokenError):
    """Raised when a JWT token has expired."""

class InvalidSignatureError(InvalidTokenError):
    """Raised when a JWT token signature is invalid."""
