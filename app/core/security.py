"""Password hashing and verification with Argon2."""

from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError

ENCODING: Final[str] = "utf-8"
MAX_PASSWORD_BYTES: Final[int] = 1024

_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using constant-time comparison."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHash):
        return False


def get_password_hash(password: str) -> str:
    """Generate a secure Argon2id hash with salt."""
    try:
        if len(password.encode(ENCODING)) > MAX_PASSWORD_BYTES:
            raise ValueError(
                f"Password exceeds {MAX_PASSWORD_BYTES} bytes when encoded"
            )

        return _hasher.hash(password)
    except Exception as e:
        raise ValueError(f"Password hashing failed: {str(e)}") from e
