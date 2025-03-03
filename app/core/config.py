"""Application configuration and settings."""

from enum import StrEnum
from functools import lru_cache

from pydantic import (
    AnyHttpUrl,
    EmailStr,
    PositiveInt,
    PostgresDsn,
    RedisDsn,
    SecretStr,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
        env_ignore_empty=True,
        validate_default=True,
    )

    # Project metadata
    PROJECT_NAME: str = "Auth-Py"
    PROJECT_VERSION: str = "0.1.0"
    PROJECT_DESCRIPTION: str = "A proof of concept authentication service with FastAPI."

    # Application settings
    FRONTEND_URL: AnyHttpUrl = AnyHttpUrl("http://localhost:3000")
    ENVIRONMENT: Environment = Environment.DEVELOPMENT

    # Security settings
    JWT_SECRET: SecretStr
    JWT_ACCESS_TOKEN_TTL_SECS: PositiveInt
    JWT_REFRESH_TOKEN_TTL_SECS: PositiveInt

    # OAuth2 settings
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: SecretStr | None = None
    APPLE_CLIENT_ID: str | None = None
    APPLE_CLIENT_SECRET: SecretStr | None = None
    APPLE_TEAM_ID: str | None = None
    APPLE_KEY_ID: str | None = None

    # Rate limiting
    RATE_LIMIT_REQUESTS: PositiveInt = 10
    RATE_LIMIT_WINDOW_SECS: PositiveInt = 60
    MAX_LOGIN_ATTEMPTS: PositiveInt = 5

    # Database settings
    DATABASE_URI: PostgresDsn

    # Redis settings
    REDIS_URI: RedisDsn

    # CORS settings
    CORS_ORIGINS: list[AnyHttpUrl] = [AnyHttpUrl("http://localhost:3000")]
    CORS_ALLOW_METHODS: list[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    CORS_ALLOW_HEADERS: list[str] = ["Authorization", "Content-Type"]

    # Cookie settings
    COOKIE_MAX_AGE_SECS: PositiveInt = 604800

    # SMTP settings
    SMTP_HOST: str
    SMTP_PORT: PositiveInt = 587
    SMTP_USER: str
    SMTP_PASSWORD: SecretStr
    SMTP_FROM_EMAIL: EmailStr
    SMTP_FROM_NAME: str = "Auth-Py"

    # Verification settings
    VERIFICATION_CODE_LENGTH: PositiveInt = 16
    VERIFICATION_CODE_TTL_SECS: PositiveInt = 3600
    VERIFICATION_URI: str = "/verify-email"
    PASSWORD_RESET_URI: str = "/reset-password"

    @field_validator("ENVIRONMENT", mode="before")
    @classmethod
    def normalize_environment(cls, v: str) -> str:
        return v.lower() if isinstance(v, str) else v


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
