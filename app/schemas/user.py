"""User data validation schemas with examples."""

from typing import Annotated, Any, Final

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
)
from pydantic import (
    EmailStr as PydanticEmailStr,
)

from app.models.user import UserRole as ModelUserRole
from app.schemas.base import BaseSchema

MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 72
MIN_TOKEN_LENGTH: Final[int] = 32
MAX_TOKEN_LENGTH: Final[int] = 64
MAX_OAUTH_ID_LENGTH: Final[int] = 255
MAX_OAUTH_PROVIDER_LENGTH: Final[int] = 50
PHONE_PATTERN: Final[str] = r"^\+[1-9]\d{1,14}$"
EMAIL_PATTERN: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"


def normalize_email(value: PydanticEmailStr) -> PydanticEmailStr:
    """Normalize email to lowercase."""
    return value.lower()


EmailStr = Annotated[PydanticEmailStr, AfterValidator(normalize_email)]


def normalize_role(value: Any) -> Any:
    """Normalize role value to lowercase if provided as a string."""
    if type(value) is str:
        return ModelUserRole(value.lower())
    return value


UserRole = Annotated[ModelUserRole, BeforeValidator(normalize_role)]


class UserBase(BaseModel):
    """Base user data validation."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "phone": "+1234567890",
                "role": UserRole.USER,
            }
        },
        populate_by_name=True,
    )

    email: EmailStr = Field(
        description="User's email address",
        examples=["user@example.com"],
        pattern=EMAIL_PATTERN,
    )
    phone: str | None = Field(
        default=None,
        description="User's phone number in E.164 format",
        examples=["+1234567890"],
        pattern=PHONE_PATTERN,
    )
    role: UserRole = Field(
        default=UserRole.USER,
        description="User's role for authorization",
        examples=[UserRole.USER, UserRole.ADMIN],
    )


class UserCreate(UserBase):
    """New user registration data."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "phone": "+1234567890",
                "password": "strongP@ssw0rd",
                "role": UserRole.USER,
            }
        },
    )

    password: str = Field(
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
        description="User's password (will be hashed)",
        examples=["strongP@ssw0rd"],
    )


class UserUpdate(BaseModel):
    """User profile update data."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "phone": "+1234567890",
                "password": "newP@ssw0rd",
            }
        },
        populate_by_name=True,
    )

    phone: str | None = Field(
        default=None,
        description="User's phone number in E.164 format",
        examples=["+1234567890"],
        pattern=PHONE_PATTERN,
    )
    password: str | None = Field(
        default=None,
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
        description="User's password (will be hashed)",
        examples=["newP@ssw0rd"],
    )


class UserResponse(UserBase, BaseSchema):
    """User data for responses."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": "123e4567-e89b-12d3-a456-426614174000",
                "email": "user@example.com",
                "phone": "+1234567890",
                "role": UserRole.USER,
                "is_verified": True,
                "is_active": True,
                "oauth_provider": "google",
                "oauth_id": "123456789",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
            }
        },
    )

    is_verified: bool = Field(
        description="Whether the user's email is verified",
    )
    is_active: bool = Field(
        description="Whether the user account is active",
    )
    oauth_provider: str | None = Field(
        default=None,
        max_length=MAX_OAUTH_PROVIDER_LENGTH,
        description="OAuth provider name (e.g. google, github)",
        examples=["google", "github", "apple"],
    )
    oauth_id: str | None = Field(
        default=None,
        max_length=MAX_OAUTH_ID_LENGTH,
        description="OAuth provider's unique identifier",
        examples=["123456789"],
    )


class OAuthUserCreate(BaseModel):
    """OAuth user registration data."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "oauth_provider": "google",
                "oauth_id": "123456789",
                "is_verified": True,
            }
        },
    )

    email: EmailStr = Field(
        description="User's email address",
        examples=["user@example.com"],
        pattern=EMAIL_PATTERN,
    )
    oauth_provider: str = Field(
        max_length=MAX_OAUTH_PROVIDER_LENGTH,
        description="OAuth provider name",
        examples=["google", "github", "apple"],
    )
    oauth_id: str = Field(
        max_length=MAX_OAUTH_ID_LENGTH,
        description="OAuth provider's unique identifier",
        examples=["123456789"],
    )
    is_verified: bool = Field(
        default=True,
        description="Whether the email is verified by the OAuth provider",
    )


class EmailRequest(BaseModel):
    """Email-only request validation."""

    model_config = ConfigDict(
        json_schema_extra={"example": {"email": "user@example.com"}},
        populate_by_name=True,
    )

    email: EmailStr = Field(
        description="Email address",
        examples=["user@example.com"],
        pattern=EMAIL_PATTERN,
    )


class PasswordResetRequest(BaseModel):
    """Password reset request validation."""

    model_config = ConfigDict(
        json_schema_extra={"example": {"email": "user@example.com"}},
        populate_by_name=True,
    )

    email: EmailStr = Field(
        description="Email address of the account to reset",
        examples=["user@example.com"],
    )


class PasswordResetVerify(BaseModel):
    """Password reset verification."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"token": "abc123...", "password": "newP@ssw0rd"}
        },
        populate_by_name=True,
    )

    token: str = Field(
        description="Password reset token received via email",
        min_length=MIN_TOKEN_LENGTH,
        max_length=MAX_TOKEN_LENGTH,
    )
    password: str = Field(
        description="New password",
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
        examples=["newP@ssw0rd"],
    )


class UserRoleUpdate(BaseModel):
    """User role update data."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "role": UserRole.ADMIN,
            }
        },
        populate_by_name=True,
    )

    role: UserRole = Field(
        description="User role",
        examples=[UserRole.USER, UserRole.ADMIN],
    )


class EmailVerificationRequest(BaseModel):
    """Email verification request data."""

    model_config = ConfigDict(json_schema_extra={"example": {"code": "abc123..."}})

    code: str = Field(
        description="Email verification code received via email",
        min_length=MIN_TOKEN_LENGTH,
        max_length=MAX_TOKEN_LENGTH,
        examples=["abc123..."],
    )


class EmailChangeVerify(BaseModel):
    """Email change verification data."""

    model_config = ConfigDict(json_schema_extra={"example": {"code": "abc123..."}})

    code: str = Field(
        description="Email change verification code received via email",
        min_length=MIN_TOKEN_LENGTH,
        max_length=MAX_TOKEN_LENGTH,
        examples=["abc123..."],
    )
