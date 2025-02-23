"""User data validation schemas with examples.

Example:
```python
# Create new user
user = UserCreate(
    email="user@example.com",
    password="strongP@ssw0rd",  # Min 8 chars
    phone="+1234567890",        # Optional, E.164 format
    roles=["user"]              # Default: ["user"]
)

# Update user
update = UserUpdate(
    phone="+1987654321",
    password="newP@ssw0rd",
    is_active=True
)

# Password reset flow
reset_req = PasswordResetRequest(email="user@example.com")
reset_verify = PasswordResetVerify(
    token="abc123...",          # From email
    password="newP@ssw0rd"      # Min 8 chars
)
```

Critical Notes:
- Passwords: 8-72 chars (bcrypt limit)
- Phone: E.164 format (+1234567890)
- Roles: Default is ["user"]
- Email validation uses EmailStr
- All fields validated before DB ops
"""

from typing import Final

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.schemas.base import BaseSchema

# Constants
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 72  # bcrypt limit
MIN_TOKEN_LENGTH: Final[int] = 32
MAX_TOKEN_LENGTH: Final[int] = 64
DEFAULT_ROLE: Final[str] = "user"
PHONE_PATTERN: Final[str] = r"^\+[1-9]\d{1,14}$"
EMAIL_PATTERN: Final[str] = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"


class UserBase(BaseModel):
    """Base user data validation."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "phone": "+1234567890",
                "roles": ["user"],
            }
        },
        populate_by_name=True,
    )

    email: EmailStr = Field(
        description="User's email address",
        examples=["user@example.com"],
    )
    phone: str | None = Field(
        default=None,
        description="User's phone number in E.164 format",
        examples=["+1234567890"],
        pattern=PHONE_PATTERN,
    )
    roles: list[str] = Field(
        default_factory=lambda: [DEFAULT_ROLE],
        description="User's roles for authorization",
        examples=[["user"], ["user", "admin"]],
    )


class UserCreate(UserBase):
    """New user registration data."""

    password: str = Field(
        min_length=MIN_PASSWORD_LENGTH,
        max_length=MAX_PASSWORD_LENGTH,
        description="User's password (will be hashed)",
        examples=["strongP@ssw0rd"],
    )


class UserUpdate(BaseModel):
    """User data update fields."""

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "phone": "+1234567890",
                "password": "newP@ssw0rd",
                "is_active": True,
                "is_verified": True,
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
        description="User's new password (will be hashed)",
        examples=["newP@ssw0rd"],
    )
    is_active: bool | None = Field(
        default=None,
        description="Whether the user account is active",
    )
    is_verified: bool | None = Field(
        default=None,
        description="Whether the user's email is verified",
    )

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str | None) -> str | None:
        """Ensure phone is in E.164 format if provided."""
        if v is None:
            return None
        assert v.startswith("+"), "Phone must start with +"
        assert len(v) >= 8, "Phone too short"
        assert len(v) <= 16, "Phone too long"
        assert v[1:].isdigit(), "Invalid phone format"
        return v


class UserResponse(UserBase, BaseSchema):
    """User data for responses."""

    is_verified: bool = Field(
        description="Whether the user's email is verified",
    )
    is_active: bool = Field(
        description="Whether the user account is active",
    )
    social_id: dict[str, str] = Field(
        description="User's social login IDs",
        examples=[{"google": "123", "apple": "456"}],
    )


class EmailRequest(BaseModel):
    """Email-only request validation."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com"
            }
        },
        populate_by_name=True,
    )

    email: str = Field(
        description="Email address",
        examples=["user@example.com"],
        pattern=EMAIL_PATTERN,
    )


class PasswordResetRequest(BaseModel):
    """Password reset request validation."""

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com"
            }
        },
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
            "example": {
                "token": "abc123...",
                "password": "newP@ssw0rd"
            }
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
