"""Security utilities for authentication."""

from app.core.types import checkpw, gensalt, hashpw


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
