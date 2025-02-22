"""Test cases for the register endpoint."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock

import pytest
from fastapi import status
from httpx import AsyncClient, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import AuditLog, User


@pytest.mark.asyncio
async def test_register_success(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test successful user registration."""
    # Test data
    user_data = {
        "email": "new@example.com",
        "password": "strongpassword123",
        "phone": "+1234567890",
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == user_data["email"]
    assert data["phone"] == user_data["phone"]
    assert "password" not in data

    # Verify database
    async with test_session.begin():
        stmt = select(User).where(User.email == user_data["email"])
        result = await test_session.execute(stmt)
        user = result.scalar_one()
        assert user is not None
        assert user.email == user_data["email"]
        assert user.phone == user_data["phone"]
        assert user.verification_code is not None
        assert not user.is_verified


@pytest.mark.asyncio
async def test_register_duplicate_email(
    test_client: AsyncClient,
    test_user: User,
) -> None:
    """Test registration with existing email."""
    # Test data
    user_data = {
        "email": test_user.email,  # Use existing email
        "password": "strongpassword123",
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    data = response.json()
    assert "Email already registered" in data["detail"]


@pytest.mark.asyncio
async def test_register_invalid_email(test_client: AsyncClient) -> None:
    """Test registration with invalid email."""
    # Test data
    user_data = {
        "email": "invalid-email",  # Invalid email format
        "password": "strongpassword123",
        "phone": "+1234567890",
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "email" in str(data["detail"]).lower()


@pytest.mark.asyncio
async def test_register_weak_password(test_client: AsyncClient) -> None:
    """Test registration with weak password."""
    # Test data
    user_data = {
        "email": "new@example.com",
        "password": "weak",  # Too short
        "phone": "+1234567890",
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "password" in str(data["detail"]).lower()


@pytest.mark.asyncio
async def test_register_invalid_phone(test_client: AsyncClient) -> None:
    """Test registration with invalid phone number."""
    # Test data
    user_data = {
        "email": "new@example.com",
        "password": "strongpassword123",
        "phone": "123",  # Invalid phone format
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "phone" in str(data["detail"]).lower()


@pytest.mark.asyncio
async def test_register_verification_email_sent(
    test_client: AsyncClient,
    test_session: AsyncSession,
    mock_email_service: AsyncMock,
) -> None:
    """Test that verification email is sent on registration."""
    # Test data
    user_data = {
        "email": "new@example.com",
        "password": "strongpassword123",
        "phone": "+1234567890",
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_201_CREATED

    # Verify user and verification code
    async with test_session.begin():
        stmt = select(User).where(User.email == user_data["email"])
        result = await test_session.execute(stmt)
        user = result.scalar_one()
        assert user.verification_code is not None
        assert len(user.verification_code) == 32  # 16 bytes in hex = 32 chars
        assert user.verification_code_expires_at is not None
        assert user.verification_code_expires_at > datetime.now(UTC)
        assert user.verification_code_expires_at < datetime.now(UTC) + timedelta(
            hours=settings.VERIFICATION_CODE_EXPIRES_HOURS + 1
        )

    # Verify email was sent
    mock_email_service.assert_called_once()
    call_args = mock_email_service.call_args[1]  # Get kwargs
    assert call_args["to_email"] == user_data["email"]
    assert "Verify your email address" in call_args["subject"]
    assert user.verification_code in call_args["html_content"]
    assert user.verification_code in call_args["text_content"]


@pytest.mark.asyncio
async def test_register_audit_log_created(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test that audit log is created for registration."""
    # Test data
    user_data = {
        "email": "new@example.com",
        "password": "strongpassword123",
        "phone": "+1234567890",
    }

    # Make request
    response = await test_client.post("/api/v1/auth/register", json=user_data)

    # Assert response
    assert response.status_code == status.HTTP_201_CREATED
    user_id = response.json()["id"]

    # Verify audit log
    async with test_session.begin():
        stmt = select(AuditLog).where(
            AuditLog.user_id == user_id,
            AuditLog.action == "register",
        )
        result = await test_session.execute(stmt)
        audit_log = result.scalar_one()
        assert audit_log is not None
        assert audit_log.ip_address == "127.0.0.1"  # Test client IP
        assert "python-httpx" in audit_log.user_agent.lower()
        assert audit_log.details == "User registration"


@pytest.mark.asyncio
async def test_register_password_complexity(
    test_client: AsyncClient,
) -> None:
    """Test password complexity requirements."""
    test_cases = [
        ("short", False),  # Too short (< 8 chars)
        ("strongpassword123", True),  # Valid password
        ("a" * 73, False),  # Too long (> 72 chars, bcrypt limit)
    ]

    for password, should_pass in test_cases:
        # Test data
        user_data = {
            "email": f"test{password}@example.com",  # Unique email for each test
            "password": password,
            "phone": None,  # Optional phone
        }

        # Make request
        response = await test_client.post("/api/v1/auth/register", json=user_data)

        # Assert response
        expected_status = status.HTTP_201_CREATED if should_pass else status.HTTP_422_UNPROCESSABLE_ENTITY
        assert response.status_code == expected_status, f"Failed for password: {password}"


@pytest.mark.asyncio
async def test_register_concurrent_same_email(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test concurrent registration attempts with the same email."""
    # Test data
    user_data = {
        "email": "concurrent@example.com",
        "password": "strongpassword123",
        "phone": None,  # Make phone optional to avoid unique constraint issues
    }

    # Make concurrent requests
    async def make_request() -> Response | Exception:
        try:
            return await test_client.post("/api/v1/auth/register", json=user_data)
        except Exception as e:
            return e

    # Create 3 concurrent requests
    responses = await asyncio.gather(
        *[make_request() for _ in range(3)],
        return_exceptions=True,
    )

    # Count successful registrations
    success_count = sum(
        1 for r in responses
        if isinstance(r, Response) and r.status_code == status.HTTP_201_CREATED
    )
    assert success_count == 1

    # Verify database has only one user
    async with test_session.begin():
        stmt = select(User).where(User.email == user_data["email"])
        result = await test_session.execute(stmt)
        users = result.scalars().all()
        assert len(users) == 1
