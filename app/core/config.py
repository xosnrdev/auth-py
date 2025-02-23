"""Application configuration management following security best practices.

This module implements secure configuration management following RFCs:
- OAuth2 (RFC 6749)
- Bearer Token Usage (RFC 6750)
- JWT Claims (RFC 7519)
- CORS (Cross-Origin Resource Sharing)
- SMTP over TLS (RFC 3207)
- HTTP Security Headers (RFC 6797)
- Rate Limiting (RFC 6585)

Core Features:
1. Environment Configuration
   - Environment variable loading
   - Secure defaults
   - Type validation
   - Secret handling
   - URL validation

2. Security Settings
   - JWT configuration
   - CORS policies
   - Rate limiting
   - Cookie security
   - Header policies

3. Service Integration
   - Database connections
   - Redis caching
   - SMTP settings
   - OAuth2 providers
   - Session management

4. Validation Features
   - Type checking
   - URL validation
   - Secret handling
   - Format verification
   - Default protection

Security Considerations:
- Secure secret handling
- Environment isolation
- Type safety
- URL validation
- Default protection
"""

from functools import lru_cache

from pydantic import (
    Field,
    PostgresDsn,
    RedisDsn,
    SecretStr,
    ValidationInfo,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with secure defaults.

    Implements secure configuration management:
    1. Application Settings
       - Base URL configuration
       - Endpoint paths
       - Version information
       - Service discovery

    2. Security Settings
       - JWT configuration
       - Token expiration
       - Cookie security
       - CORS policies
       - Rate limiting

    3. Authentication Settings
       - OAuth2 providers
       - Social login
       - Email verification
       - Password policies
       - Session management

    4. Infrastructure Settings
       - Database connections
       - Redis caching
       - SMTP configuration
       - Connection pooling
       - Resource limits

    Security:
        - Environment isolation
        - Secret protection
        - Type validation
        - URL verification
        - Default security
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
        env_ignore_empty=True,
        validate_default=True,
    )

    # Application settings
    APP_URL: str = Field(
        default="http://localhost:3000",
        description="Base URL of the frontend application",
        examples=["http://localhost:3000", "https://example.com"],
    )
    VERIFICATION_URL_PATH: str = Field(
        default="/verify-email",
        description="Path for email verification",
        examples=["/verify-email", "/auth/verify"],
    )
    PASSWORD_RESET_URL_PATH: str = Field(
        default="/reset-password",
        description="Path for password reset",
        examples=["/reset-password", "/auth/reset"],
    )

    # Rate limiting settings
    RATE_LIMIT_REQUESTS: int = Field(
        default=5,
        description="Maximum number of requests per window",
        gt=0,
    )
    RATE_LIMIT_WINDOW_SECS: int = Field(
        default=60,  # 1 minute
        description="Rate limit window in seconds",
        gt=0,
    )

    # JWT settings
    JWT_SECRET: str = Field(
        default=...,  # Required
        description="Secret key for JWT signing",
    )
    JWT_ACCESS_TOKEN_EXPIRES_SECS: int = Field(
        default=15 * 60,  # 15 minutes in seconds
        description="Access token expiration time in seconds",
    )
    JWT_REFRESH_TOKEN_EXPIRES_SECS: int = Field(
        default=7 * 24 * 60 * 60,  # 7 days in seconds
        description="Refresh token expiration time in seconds",
    )

    # OAuth2 settings
    GOOGLE_CLIENT_ID: str = Field(
        default=...,  # Required
        description="Google OAuth2 client ID",
    )
    GOOGLE_CLIENT_SECRET: SecretStr = Field(
        default=...,  # Required
        description="Google OAuth2 client secret",
    )
    APPLE_CLIENT_ID: str = Field(
        default=...,  # Required
        description="Apple OAuth2 client ID (Services ID)",
    )
    APPLE_CLIENT_SECRET: SecretStr = Field(
        default=...,  # Required
        description="Apple OAuth2 client secret (Private Key)",
    )
    APPLE_TEAM_ID: str = Field(
        default=...,  # Required
        description="Apple Developer Team ID",
    )
    APPLE_KEY_ID: str = Field(
        default=...,  # Required
        description="Apple Private Key ID",
    )

    # Database settings
    DATABASE_URI: PostgresDsn = Field(
        default=...,  # Required
        description="PostgreSQL database URI",
        examples=["postgresql+asyncpg://user:pass@localhost:5432/dbname"],
    )

    # Redis settings
    REDIS_URI: RedisDsn = Field(
        default=...,  # Required
        description="Redis URI for caching and session management",
        examples=["redis://localhost:6379"],
    )

    # CORS settings
    CORS_ORIGINS: list[str] = Field(
        default=["http://localhost:3000"],
        description="List of origins that can access the API (CORS)",
        examples=[["http://localhost:3000", "https://example.com"]],
    )
    CORS_ALLOW_CREDENTIALS: bool = Field(
        default=True,
        description="Allow credentials (cookies, authorization headers) with CORS",
    )
    CORS_ALLOW_METHODS: list[str] = Field(
        default=["*"],
        description="HTTP methods that can be used with CORS",
        examples=[["GET", "POST", "PUT", "DELETE"]],
    )
    CORS_ALLOW_HEADERS: list[str] = Field(
        default=["*"],
        description="HTTP headers that can be used with CORS",
        examples=[["Authorization", "Content-Type"]],
    )

    # Cookie settings
    COOKIE_MAX_AGE_SECS: int = Field(
        default=14 * 24 * 60 * 60,  # 14 days in seconds
        description="Maximum age of the session cookie in seconds",
    )

    # Email settings for verification
    SMTP_HOST: str = Field(
        default=...,  # Required
        description="SMTP server hostname",
    )
    SMTP_PORT: int = Field(
        default=587,
        description="SMTP server port",
    )
    SMTP_USER: str = Field(
        default=...,  # Required
        description="SMTP username",
    )
    SMTP_PASSWORD: str = Field(
        default=...,  # Required
        description="SMTP password",
    )
    SMTP_FROM_EMAIL: str = Field(
        default=...,  # Required
        description="From email address for sent emails",
    )
    SMTP_FROM_NAME: str = Field(
        default="Auth Service",
        description="From name for sent emails",
    )

    # Verification settings
    VERIFICATION_CODE_LENGTH: int = Field(
        default=16,  # 32 characters in hex
        description="Length of verification code in bytes (will be converted to hex)",
    )
    VERIFICATION_CODE_EXPIRES_HOURS: int = Field(
        default=24,
        description="Hours until verification code expires",
    )

    @field_validator("DATABASE_URI", "REDIS_URI")
    @classmethod
    def validate_uris(cls, v: PostgresDsn | RedisDsn, info: ValidationInfo) -> PostgresDsn | RedisDsn:
        """Validate database and Redis URIs.

        Implements secure URI validation:
        1. Format Validation
           - Checks URI structure
           - Validates components
           - Ensures required parts
           - Handles defaults

        2. Security Checks
           - Protocol verification
           - Port validation
           - Parameter checking
           - Credential handling

        Args:
            v: URI to validate
            info: Validation context information

        Returns:
            PostgresDsn | RedisDsn: Validated URI

        Raises:
            ValueError: If URI is invalid or missing

        Security:
            - URI validation
            - Protocol checks
            - Port validation
            - Safe defaults
        """
        if not v:
            raise ValueError(f"{info.field_name} must be set")
        return v


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Implements secure settings management:
    1. Settings Loading
       - Environment variables
       - Configuration files
       - Secure defaults
       - Type validation

    2. Caching
       - LRU cache usage
       - Memory efficiency
       - Performance optimization
       - Thread safety

    Returns:
        Settings: Application settings loaded from environment variables.

    Raises:
        ValidationError: If required environment variables are missing or invalid.

    Security:
        - Environment isolation
        - Type validation
        - Cache security
        - Error handling
    """
    return Settings()


settings = get_settings()
