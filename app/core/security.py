"""Security utilities for authentication."""

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from app.core.config import settings
from app.core.types import (
    ExpiredSignatureError,
    InvalidSignatureError,
    InvalidTokenError,
    checkpw,
    decode,
    encode,
    gensalt,
    hashpw,
)
from app.schemas import TokenPayload


def create_jwt_token(
    subject: UUID,
    token_type: str = "access",
    expires_delta: timedelta | None = None,
) -> tuple[str, datetime]:
    """Create a JWT token following RFC 9068 standards.

    Args:
        subject: Subject (user ID) for the token
        token_type: Type of token ("access" or "refresh")
        expires_delta: Optional expiration delta

    Returns:
        tuple[str, datetime]: JWT token and expiration datetime
    """
    if expires_delta is None:
        expires_delta = (
            timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
            if token_type == "access"
            else timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
        )

    expires_at = datetime.now(UTC) + expires_delta
    to_encode: dict[str, Any] = {
        # RFC 7519 registered claims
        "iss": settings.JWT_ISSUER,  # Issuer
        "sub": str(subject),  # Subject
        "aud": settings.JWT_AUDIENCE,  # Audience
        "exp": int(expires_at.timestamp()),  # Expiration time
        "iat": int(time.time()),  # Issued at
        "nbf": int(time.time()),  # Not before
        "jti": str(subject),  # JWT ID (using user ID)
        # Custom claims
        "type": token_type,  # Token type for client differentiation
    }

    encoded_jwt = encode(
        to_encode,
        settings.JWT_PRIVATE_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )

    return encoded_jwt, expires_at


def decode_jwt_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token following RFC 9068 standards.

    Args:
        token: JWT token to decode

    Returns:
        dict[str, Any]: Decoded token payload

    Raises:
        ValueError: If token is invalid or payload is invalid
    """
    try:
        payload = decode(
            token,
            settings.JWT_PUBLIC_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER,
        )
        TokenPayload(**payload)  # Validate payload
        return payload
    except (InvalidTokenError, ExpiredSignatureError, InvalidSignatureError) as e:
        raise ValueError(f"Invalid token: {str(e)}")
    except ValidationError as e:
        raise ValueError(f"Invalid token payload: {str(e)}")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash.

    Args:
        plain_password: Plain text password
        hashed_password: Hashed password

    Returns:
        bool: True if password matches hash
    """
    return checkpw(
        plain_password.encode("utf-8"),
        hashed_password.encode("utf-8"),
    )


def get_password_hash(password: str) -> str:
    """Hash a password.

    Args:
        password: Plain text password

    Returns:
        str: Hashed password
    """
    salt = gensalt(rounds=12)  # Higher rounds = more secure but slower
    hashed = hashpw(
        password.encode("utf-8"),
        salt,
    )
    return hashed.decode("utf-8")
