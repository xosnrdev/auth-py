"""Type stubs for external libraries."""

import bcrypt


# Type stubs for bcrypt
def gensalt(rounds: int = 12) -> bytes:
    """Generate a salt for password hashing."""
    return bcrypt.gensalt(rounds=rounds)

def hashpw(password: bytes, salt: bytes) -> bytes:
    """Hash a password with a salt."""
    return bcrypt.hashpw(password, salt)

def checkpw(password: bytes, hashed: bytes) -> bool:
    """Check if a password matches a hash."""
    return bcrypt.checkpw(password, hashed)
