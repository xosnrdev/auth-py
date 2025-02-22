from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
        env_ignore_empty=True,
        validate_default=True,
    )

    # Database settings
    DATABASE_URI: PostgresDsn = Field(
        default=...,  # Ellipsis means the field is required
        description="PostgreSQL database URI",
        examples=["postgresql+asyncpg://user:pass@localhost:5432/dbname"],
    )

    # Redis settings
    REDIS_URI: RedisDsn = Field(
        default=...,  # Ellipsis means the field is required
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
    COOKIE_NAME: str = Field(
        default="session",
        description="Name of the session cookie",
    )
    COOKIE_MAX_AGE: int = Field(
        default=14 * 24 * 60 * 60,  # 14 days in seconds
        description="Maximum age of the session cookie in seconds",
    )
    COOKIE_SECURE: bool = Field(
        default=True,
        description="Only send cookie over HTTPS",
    )
    COOKIE_HTTPONLY: bool = Field(
        default=True,
        description="Prevent JavaScript access to cookie",
    )
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = Field(
        default="lax",
        description="SameSite cookie policy (lax, strict, or none)",
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
        """Validate that URIs are properly formatted."""
        if not v:
            raise ValueError(f"{info.field_name} must be set")
        return v


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings: Application settings loaded from environment variables.

    Raises:
        ValidationError: If required environment variables are missing or invalid.
    """
    return Settings()  # Environment file is configured in model_config


settings = get_settings()
