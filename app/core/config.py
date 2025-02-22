from functools import lru_cache

from pydantic import Field, PostgresDsn, RedisDsn, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
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
