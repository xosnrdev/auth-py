"""Test cases for the login endpoint."""

import pytest
from fastapi import status
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.models import AuditLog, User

pytestmark = pytest.mark.asyncio(loop_scope="function")


@pytest.mark.asyncio
async def test_login_success(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test successful login with valid credentials."""
    # Create test user
    user = User(
        email="test@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=True,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    # Test data
    login_data = {
        "username": "test@example.com",
        "password": "testpassword",
    }

    # Make request
    response = await test_client.post(
        "/api/v1/auth/login",
        data=login_data,
    )

    # Assert response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0

    # Verify audit log using ORM
    stmt = select(AuditLog).where(
        AuditLog.user_id == user.id,
        AuditLog.action == "login",
    )
    result = await test_session.execute(stmt)
    audit_log = result.scalar_one()
    assert audit_log is not None
    assert audit_log.details == "Successful login"


@pytest.mark.asyncio
async def test_login_invalid_credentials(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test login with invalid credentials."""
    # Create test user
    user = User(
        email="test@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=True,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    # Test cases
    test_cases = [
        {
            "username": "test@example.com",
            "password": "wrongpassword",
            "detail": "Invalid credentials",
        },
        {
            "username": "wrong@example.com",
            "password": "testpassword",
            "detail": "Invalid credentials",
        },
    ]

    for case in test_cases:
        # Make request
        response = await test_client.post(
            "/api/v1/auth/login",
            data=case,
        )

        # Assert response
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert response.json()["detail"] == case["detail"]
        assert "WWW-Authenticate" in response.headers


@pytest.mark.asyncio
async def test_login_unverified_user(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test login with unverified email."""
    # Create unverified user
    user = User(
        email="unverified@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=False,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    # Test data
    login_data = {
        "username": "unverified@example.com",
        "password": "testpassword",
    }

    # Make request
    response = await test_client.post(
        "/api/v1/auth/login",
        data=login_data,
    )

    # Assert response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Email not verified"


@pytest.mark.asyncio
async def test_login_inactive_user(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test login with inactive account."""
    # Create inactive user
    user = User(
        email="inactive@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=True,
        is_active=False,
    )
    test_session.add(user)
    await test_session.commit()

    # Test data
    login_data = {
        "username": "inactive@example.com",
        "password": "testpassword",
    }

    # Make request
    response = await test_client.post(
        "/api/v1/auth/login",
        data=login_data,
    )

    # Assert response
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.json()["detail"] == "Account is disabled"


@pytest.mark.asyncio
async def test_login_web_client(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test login with web client (cookie-based)."""
    # Create test user
    user = User(
        email="web@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=True,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    # Test data
    login_data = {
        "username": "web@example.com",
        "password": "testpassword",
    }

    # Make request with Accept: text/html header
    response = await test_client.post(
        "/api/v1/auth/login",
        data=login_data,
        headers={"Accept": "text/html"},
    )

    # Assert response
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert data["refresh_token"] is None  # No refresh token in response for web clients
    assert "refresh_token" in response.cookies  # Refresh token in cookie


@pytest.mark.asyncio
async def test_login_rate_limit(
    test_client: AsyncClient,
    test_session: AsyncSession,
) -> None:
    """Test login rate limiting."""
    # Create test user
    user = User(
        email="ratelimit@example.com",
        password_hash=get_password_hash("testpassword"),
        is_verified=True,
        is_active=True,
    )
    test_session.add(user)
    await test_session.commit()

    # Test data
    login_data = {
        "username": "ratelimit@example.com",
        "password": "wrongpassword",
    }

    # Make multiple failed login attempts
    for i in range(6):
        response = await test_client.post(
            "/api/v1/auth/login",
            data=login_data,
        )
        if i < 5:
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
        else:
            assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
            assert "retry-after" in [k.lower() for k in response.headers.keys()]
