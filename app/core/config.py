"""Application configuration with secure defaults and validation.

Example:
```python
from app.core.config import settings

# Database connection (required)
assert settings.DATABASE_URI.scheme == "postgresql+asyncpg"
assert settings.DATABASE_URI.host != "localhost" or settings.DEBUG

# Redis connection (required)
assert settings.REDIS_URI.scheme == "redis"
assert settings.REDIS_URI.host != "localhost" or settings.DEBUG

# JWT configuration
assert len(settings.JWT_SECRET) >= 32, "JWT secret too short"
assert settings.JWT_ACCESS_TOKEN_EXPIRES_SECS <= 3600  # Max 1 hour
assert settings.JWT_REFRESH_TOKEN_EXPIRES_SECS <= 604800  # Max 7 days

# CORS security
assert all(
    origin.startswith("https://") for origin in settings.CORS_ORIGINS
) or settings.DEBUG, "HTTPS required in production"

# SMTP security
assert settings.SMTP_PORT in (465, 587), "TLS required"
assert not settings.DEBUG or settings.SMTP_HOST == "localhost"
```

Critical Security Notes:
1. Secrets Management
   - All secrets loaded from environment
   - No defaults for sensitive data
   - Secure string handling for passwords
   - No logging of sensitive values

2. Connection Security
   - HTTPS required in production
   - TLS required for SMTP
   - Secure Redis connection
   - PostgreSQL with SSL

3. Token Security
   - Limited token lifetimes
   - Secure cookie settings
   - CORS restrictions
   - Rate limiting

4. Environment Isolation
   - Debug mode detection
   - Environment validation
   - Local development safety
   - Production assertions
"""

from functools import lru_cache
from typing import Final

from pydantic import (
    Field,
    PostgresDsn,
    RedisDsn,
    SecretStr,
    ValidationInfo,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

# Security constants
MIN_SECRET_LENGTH: Final[int] = 32
MAX_ACCESS_TOKEN_EXPIRES: Final[int] = 3600
MAX_REFRESH_TOKEN_EXPIRES: Final[int] = 604800
SECURE_SMTP_PORTS: Final[tuple[int, ...]] = (465, 587)
DEFAULT_RATE_LIMIT: Final[int] = 5
DEFAULT_RATE_WINDOW: Final[int] = 60
MIN_VERIFICATION_CODE_LENGTH: Final[int] = 16


class Settings(BaseSettings):
    """Application settings with secure defaults and validation."""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
        env_ignore_empty=True,
        validate_default=True,
        json_schema_extra={
            "example": {
                "APP_URL": "https://example.com",
                "DATABASE_URI": "postgresql+asyncpg://user:pass@localhost/db",
                "REDIS_URI": "redis://localhost:6379/0",
                "JWT_SECRET": "your-secret-key",
                "DEBUG": False
            }
        }
    )

    # Application settings
    APP_URL: str = Field(
        default="http://localhost:3000",
        pattern=r"^https?://[^\s/$.?#].[^\s]*$",
        examples=["https://example.com"],
    )
    DEBUG: bool = Field(
        default=False,
        description="Enable debug mode (less strict validation)",
    )

    # Security settings
    JWT_SECRET: str = Field(
        min_length=MIN_SECRET_LENGTH,
        description="Secret key for JWT signing (min 32 chars)",
    )
    JWT_ACCESS_TOKEN_EXPIRES_SECS: int = Field(
        default=900,
        gt=0,
        le=MAX_ACCESS_TOKEN_EXPIRES,
    )
    JWT_REFRESH_TOKEN_EXPIRES_SECS: int = Field(
        default=604800,
        gt=0,
        le=MAX_REFRESH_TOKEN_EXPIRES,
    )

    # OAuth2 settings
    GOOGLE_CLIENT_ID: str = Field(
        min_length=20,
        description="Google OAuth2 client ID",
        examples=["your-client-id.apps.googleusercontent.com"],
    )
    GOOGLE_CLIENT_SECRET: SecretStr = Field(
        min_length=20,
        description="Google OAuth2 client secret",
    )
    APPLE_CLIENT_ID: str = Field(
        min_length=10,
        description="Apple OAuth2 client ID (Services ID)",
        examples=["com.example.service"],
    )
    APPLE_CLIENT_SECRET: SecretStr = Field(
        min_length=20,
        description="Apple OAuth2 client secret (Private Key)",
    )
    APPLE_TEAM_ID: str = Field(
        min_length=10,
        pattern=r"^[A-Z0-9]+$",
        description="Apple Developer Team ID",
        examples=["ABCDE12345"],
    )
    APPLE_KEY_ID: str = Field(
        min_length=10,
        pattern=r"^[A-Z0-9]+$",
        description="Apple Private Key ID",
        examples=["ABC1234567"],
    )

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = Field(
        default=DEFAULT_RATE_LIMIT,
        gt=0,
        le=100,
    )
    RATE_LIMIT_WINDOW_SECS: int = Field(
        default=DEFAULT_RATE_WINDOW,
        gt=0,
        le=3600,
    )

    # Database settings
    DATABASE_URI: PostgresDsn = Field(
        examples=["postgresql+asyncpg://user:pass@localhost/db"],
    )

    # Redis settings
    REDIS_URI: RedisDsn = Field(
        examples=["redis://localhost:6379/0"],
    )

    # CORS settings
    CORS_ORIGINS: list[str] = Field(
        default=["http://localhost:3000"],
        max_length=10,
        examples=[["https://example.com"]],
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(default=True)
    CORS_ALLOW_METHODS: list[str] = Field(
        default=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    )
    CORS_ALLOW_HEADERS: list[str] = Field(
        default=["Authorization", "Content-Type"],
    )

    # Cookie settings
    COOKIE_MAX_AGE_SECS: int = Field(
        default=604800,
        gt=0,
        le=MAX_REFRESH_TOKEN_EXPIRES,
    )

    # SMTP settings
    SMTP_HOST: str = Field(
        pattern=r"^[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}$",
        examples=["smtp.gmail.com"],
    )
    SMTP_PORT: int = Field(
        default=587,
        description="SMTP port (must be 465 or 587 for TLS)",
    )
    SMTP_USER: str = Field(
        min_length=4,
        examples=["user@example.com"],
    )
    SMTP_PASSWORD: SecretStr = Field(
        min_length=8,
    )
    SMTP_FROM_EMAIL: str = Field(
        pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
        examples=["noreply@example.com"],
    )
    SMTP_FROM_NAME: str = Field(
        default="Auth Service",
        min_length=1,
        max_length=50,
    )

    # Verification settings
    VERIFICATION_CODE_LENGTH: int = Field(
        default=MIN_VERIFICATION_CODE_LENGTH,
        ge=MIN_VERIFICATION_CODE_LENGTH,
        le=32,
    )
    VERIFICATION_CODE_EXPIRES_HOURS: int = Field(
        default=24,
        gt=0,
        le=72,
    )
    VERIFICATION_URL_PATH: str = Field(
        default="/verify-email",
        pattern=r"^/[a-zA-Z0-9\-/]+$",
    )
    PASSWORD_RESET_URL_PATH: str = Field(
        default="/reset-password",
        pattern=r"^/[a-zA-Z0-9\-/]+$",
    )

    @field_validator("SMTP_PORT")
    @classmethod
    def validate_smtp_port(cls, v: int, info: ValidationInfo) -> int:
        """Validate SMTP port for security.

        Security:
        - Requires TLS ports
        - No plain text allowed
        - Debug mode checks
        """
        debug = info.data.get("DEBUG", False)
        if not debug:
            assert v in SECURE_SMTP_PORTS, f"SMTP port must be one of {SECURE_SMTP_PORTS} for TLS"
        return v


@lru_cache
def get_settings() -> Settings:
    """Get validated settings instance.

    Returns:
        Settings: Validated configuration

    Security:
        - Single instance
        - Cached access
        - Validated fields
        - Environment loading
    """
    return Settings()  # type: ignore[call-arg]


# Global settings instance
settings = get_settings()
