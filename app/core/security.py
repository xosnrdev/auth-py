"""Password hashing and verification with bcrypt.

Example:
```python
# Secure password hashing
from app.core.security import get_password_hash, verify_password

# Hash a new password (in user registration)
password = "MySecureP@ssw0rd123"
hashed = get_password_hash(password)
# Returns: '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LcdYxEGhKxGQhvjje'

# Verify password (in login)
valid = verify_password(password, hashed)
assert valid is True

# Invalid password fails
invalid = verify_password("wrong_password", hashed)
assert invalid is False

# Password requirements
assert len(password) >= 8, "Min 8 chars"
assert any(c.isupper() for c in password), "Need uppercase"
assert any(c.islower() for c in password), "Need lowercase"
assert any(c.isdigit() for c in password), "Need number"
```

Critical Security Notes:
1. Password Storage
   - Uses bcrypt with work factor 12
   - Includes salt automatically
   - Constant-time comparison
   - UTF-8 encoding required

2. Implementation Details
   - No plaintext storage
   - No password truncation
   - Max length: 72 bytes (bcrypt limit)
   - Salt: 16 bytes, unique per hash

3. Security Considerations
   - Immune to rainbow tables
   - Resistant to timing attacks
   - Safe against NULL byte attacks
   - Handles Unicode properly

4. Usage Requirements
   - Store complete hash string
   - Never truncate hashes
   - Use secure password policy
   - Rate limit verification
"""

from typing import Final

from bcrypt import checkpw as _checkpw
from bcrypt import gensalt as _gensalt
from bcrypt import hashpw as _hashpw

# Security constants
ENCODING: Final[str] = "utf-8"
WORK_FACTOR: Final[int] = 12
MAX_PASSWORD_BYTES: Final[int] = 72


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash using constant-time comparison.

    Implementation:
    1. Encodes strings to UTF-8 bytes
    2. Uses bcrypt's constant-time comparison
    3. Handles all string/byte conversions
    4. Returns boolean result only

    Args:
        plain_password: User-provided password to verify
        hashed_password: Stored bcrypt hash to check against

    Returns:
        bool: True if password matches hash, False otherwise

    Security:
        - Constant-time operation (no timing attacks)
        - No password length leaks
        - Safe string/byte handling
        - Exception-safe comparison

    Example:
        ```python
        stored_hash = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LcdYxEGhKxGQhvjje"
        is_valid = verify_password("user_password", stored_hash)
        ```
    """
    try:
        # Convert strings to bytes with UTF-8 encoding
        password_bytes = plain_password.encode(ENCODING)
        hash_bytes = hashed_password.encode(ENCODING)

        # Verify using constant-time comparison
        return _checkpw(password_bytes, hash_bytes)
    except (TypeError, ValueError):
        # Safely handle any encoding/comparison errors
        return False


def get_password_hash(password: str) -> str:
    """Generate a secure bcrypt hash with salt.

    Implementation:
    1. Generates 16-byte random salt
    2. Applies bcrypt with work factor 12
    3. Encodes password to UTF-8
    4. Returns complete hash string

    Args:
        password: Plain text password to hash

    Returns:
        str: Complete bcrypt hash string (includes salt)

    Security:
        - Unique salt per password
        - Safe string/byte handling
        - Standard hash format
        - Includes algorithm version

    Example:
        ```python
        hash = get_password_hash("user_password")
        # Returns: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LcdYxEGhKxGQhvjje"
        ```

    Note:
        The returned hash string contains:
        - Algorithm version ($2b$)
        - Work factor (12)
        - Salt (22 chars)
        - Hash (31 chars)
    """
    try:
        # Validate password length (bcrypt limit)
        password_bytes = password.encode(ENCODING)
        if len(password_bytes) > MAX_PASSWORD_BYTES:
            raise ValueError(f"Password exceeds {MAX_PASSWORD_BYTES} bytes when encoded")

        # Generate salt and hash
        salt = _gensalt(rounds=WORK_FACTOR)
        hash_bytes = _hashpw(password_bytes, salt)

        # Return complete hash string
        return hash_bytes.decode(ENCODING)
    except (TypeError, ValueError) as e:
        raise ValueError(f"Password hashing failed: {str(e)}") from e
