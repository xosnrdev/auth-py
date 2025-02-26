"""Password hashing and verification with bcrypt."""

from typing import Final

from bcrypt import checkpw as _checkpw
from bcrypt import gensalt as _gensalt
from bcrypt import hashpw as _hashpw

ENCODING: Final[str] = "utf-8"
WORK_FACTOR: Final[int] = 12
MAX_PASSWORD_BYTES: Final[int] = 72


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using constant-time comparison."""
    try:
        password_bytes = plain_password.encode(ENCODING)
        hash_bytes = hashed_password.encode(ENCODING)

        return _checkpw(password_bytes, hash_bytes)
    except (TypeError, ValueError):
        return False


def get_password_hash(password: str) -> str:
    """Generate a secure bcrypt hash with salt."""
    try:
        password_bytes = password.encode(ENCODING)
        if len(password_bytes) > MAX_PASSWORD_BYTES:
            raise ValueError(f"Password exceeds {MAX_PASSWORD_BYTES} bytes when encoded")

        salt = _gensalt(rounds=WORK_FACTOR)
        hash_bytes = _hashpw(password_bytes, salt)

        return hash_bytes.decode(ENCODING)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Password hashing failed: {str(e)}") from e
