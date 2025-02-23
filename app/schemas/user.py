"""User schemas for request and response models."""

from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.schemas.base import BaseSchema


class UserBase(BaseModel):
    """Base schema for user data."""

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
        pattern=r"^\+[1-9]\d{1,14}$",
    )
    roles: list[str] = Field(
        default=["user"],
        description="User's roles for authorization",
        examples=[["user"], ["user", "admin"]],
    )


class UserCreate(UserBase):
    """Schema for creating a new user."""

    password: str = Field(
        min_length=8,
        max_length=72,  # bcrypt limit
        description="User's password (will be hashed)",
        examples=["strongP@ssw0rd"],
    )


class UserUpdate(BaseModel):
    """Schema for updating a user."""

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
        pattern=r"^\+[1-9]\d{1,14}$",
    )
    password: str | None = Field(
        default=None,
        min_length=8,
        max_length=72,  # bcrypt limit
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


class UserResponse(UserBase, BaseSchema):
    """Schema for user responses."""

    is_verified: bool = Field(
        description="Whether the user's email is verified",
    )
    is_active: bool = Field(
        description="Whether the user account is active",
    )
    social_id: dict[str, Any] = Field(
        description="User's social login IDs",
        examples=[{"google": "123", "apple": "456"}],
    )


class EmailRequest(BaseModel):
    """Schema for email-only requests."""

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
        pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
    )
