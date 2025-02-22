from functools import lru_cache

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

    # JWT settings
    JWT_ALGORITHM: str = Field(
        default="RS256",
        description="Algorithm for JWT signing (must be asymmetric as per RFC 9068)",
        examples=["RS256", "ES256"],
    )
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=30,
        description="Minutes until access token expires (short-lived as per RFC 9068)",
        examples=[30],
        ge=5,  # At least 5 minutes
        le=60,  # At most 1 hour for security
    )
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=30,
        description="Days until refresh token expires (as per RFC 6749)",
        examples=[30],
        ge=1,  # At least 1 day
        le=365,  # At most 1 year
    )
    JWT_PRIVATE_KEY: str = Field(
        default=...,  # Ellipsis means the field is required
        description="RSA private key for JWT signing (PEM format)",
    )
    JWT_PUBLIC_KEY: str = Field(
        default=...,  # Ellipsis means the field is required
        description="RSA public key for JWT verification (PEM format)",
    )
    JWT_ISSUER: str = Field(
        default=...,  # Ellipsis means the field is required
        description="JWT issuer claim (iss) - must match authorization server's identifier",
        examples=["https://auth.example.com"],
    )
    JWT_AUDIENCE: list[str] = Field(
        default=...,  # Ellipsis means the field is required
        description="JWT audience claim (aud) - list of valid resource indicators",
        examples=[["https://api.example.com"]],
    )

    @field_validator("DATABASE_URI", "REDIS_URI")
    @classmethod
    def validate_uris(cls, v: PostgresDsn | RedisDsn, info: ValidationInfo) -> PostgresDsn | RedisDsn:
        """Validate that URIs are properly formatted."""
        if not v:
            raise ValueError(f"{info.field_name} must be set")
        return v

    @field_validator("JWT_PRIVATE_KEY", "JWT_PUBLIC_KEY")
    @classmethod
    def validate_jwt_keys(cls, v: str, info: ValidationInfo) -> str:
        """Validate that JWT keys are properly formatted."""
        if not v:
            raise ValueError(f"{info.field_name} must be set")
        if "BEGIN" not in v or "END" not in v:
            raise ValueError(f"{info.field_name} must be in PEM format")
        return v

    @field_validator("JWT_ALGORITHM")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm (must be asymmetric as per RFC 9068)."""
        asymmetric_algorithms = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
        if v not in asymmetric_algorithms:
            raise ValueError(
                f"JWT algorithm must be asymmetric as per RFC 9068. "
                f"Valid options are: {', '.join(sorted(asymmetric_algorithms))}"
            )
        return v

    @field_validator("JWT_ISSUER")
    @classmethod
    def validate_jwt_issuer(cls, v: str) -> str:
        """Validate JWT issuer (should be a URI as per RFC 9068)."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("JWT issuer should be a valid HTTP(S) URI")
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
