"""Test authentication endpoints and services."""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.domains.user.models import UserSession
from app.domains.user.services import AuthenticationService
from app.main import app


client = TestClient(app)


@pytest.mark.asyncio
async def test_register_user_success(db_session: AsyncSession):
    """Test successful user registration."""
    auth_service = AuthenticationService(db_session)

    user = await auth_service.register_user(
        email="test@example.com",
        password="testpassword123",
        username="testuser",
        full_name="Test User"
    )

    assert user.email == "test@example.com"
    assert user.username == "testuser"
    assert user.full_name == "Test User"
    assert user.status == "active"
    assert user.is_verified is False
    assert user.hashed_password is not None
    assert user.hashed_password != "testpassword123"


@pytest.mark.asyncio
async def test_register_user_duplicate_email(db_session: AsyncSession):
    """Test registration with duplicate email."""
    auth_service = AuthenticationService(db_session)

    # Create first user
    await auth_service.register_user(
        email="test@example.com",
        password="testpassword123"
    )

    # Try to create second user with same email
    with pytest.raises(Exception):  # Should raise ConflictError
        await auth_service.register_user(
            email="test@example.com",
            password="anotherpassword123"
        )


@pytest.mark.asyncio
async def test_authenticate_user_success(db_session: AsyncSession):
    """Test successful user authentication."""
    auth_service = AuthenticationService(db_session)

    # Register user
    user = await auth_service.register_user(
        email="test@example.com",
        password="testpassword123",
        username="testuser"
    )

    # Authenticate with email
    auth_user = await auth_service.authenticate_user(
        email_or_username="test@example.com",
        password="testpassword123"
    )

    assert auth_user is not None
    assert auth_user.id == user.id
    assert auth_user.email == "test@example.com"

    # Authenticate with username
    auth_user = await auth_service.authenticate_user(
        email_or_username="testuser",
        password="testpassword123"
    )

    assert auth_user is not None
    assert auth_user.id == user.id


@pytest.mark.asyncio
async def test_authenticate_user_wrong_password(db_session: AsyncSession):
    """Test authentication with wrong password."""
    auth_service = AuthenticationService(db_session)

    # Register user
    await auth_service.register_user(
        email="test@example.com",
        password="testpassword123"
    )

    # Try to authenticate with wrong password
    auth_user = await auth_service.authenticate_user(
        email_or_username="test@example.com",
        password="wrongpassword"
    )

    assert auth_user is None


@pytest.mark.asyncio
async def test_create_user_session(db_session: AsyncSession):
    """Test creating user session with tokens."""
    auth_service = AuthenticationService(db_session)

    # Register user
    user = await auth_service.register_user(
        email="test@example.com",
        password="testpassword123"
    )

    # Create session
    tokens = await auth_service.create_user_session(
        user=user,
        ip_address="127.0.0.1",
        user_agent="TestClient"
    )

    assert "access_token" in tokens
    assert "refresh_token" in tokens
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] == settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    # Check session in database
    result = await db_session.execute(
        select(UserSession).where(UserSession.user_id == user.id)
    )
    session = result.scalar_one_or_none()

    assert session is not None
    assert session.user_id == user.id
    assert session.is_active is True
    assert session.ip_address == "127.0.0.1"


def test_register_endpoint():
    """Test registration API endpoint."""
    response = client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpassword123",
            "username": "testuser",
            "full_name": "Test User"
        }
    )

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"
    assert data["full_name"] == "Test User"
    assert "id" in data
    assert "created_at" in data


def test_login_endpoint():
    """Test login API endpoint."""
    # First register a user
    client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpassword123",
            "username": "testuser"
        }
    )

    # Then login
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={
            "email_or_username": "test@example.com",
            "password": "testpassword123"
        }
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data


def test_login_invalid_credentials():
    """Test login with invalid credentials."""
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={
            "email_or_username": "nonexistent@example.com",
            "password": "wrongpassword"
        }
    )

    assert response.status_code == 401
    assert "Invalid credentials" in response.json()["detail"]


def test_protected_endpoint_without_token():
    """Test accessing protected endpoint without token."""
    response = client.get(f"{settings.API_V1_STR}/auth/me")

    assert response.status_code == 401
    assert "Not authenticated" in response.json()["detail"]


def test_protected_endpoint_with_token():
    """Test accessing protected endpoint with valid token."""
    # Register and login
    client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpassword123",
            "username": "testuser"
        }
    )

    login_response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={
            "email_or_username": "test@example.com",
            "password": "testpassword123"
        }
    )
    token = login_response.json()["access_token"]

    # Access protected endpoint
    response = client.get(
        f"{settings.API_V1_STR}/auth/me",
        headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"
    assert data["username"] == "testuser"


def test_refresh_token_endpoint():
    """Test token refresh endpoint."""
    # Register and login
    client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpassword123",
            "username": "testuser"
        }
    )

    login_response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={
            "email_or_username": "test@example.com",
            "password": "testpassword123"
        }
    )
    refresh_token = login_response.json()["refresh_token"]

    # Refresh token
    response = client.post(
        f"{settings.API_V1_STR}/auth/refresh",
        json={"refresh_token": refresh_token}
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "expires_in" in data


def test_logout_endpoint():
    """Test logout endpoint."""
    # Register and login
    client.post(
        f"{settings.API_V1_STR}/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpassword123",
            "username": "testuser"
        }
    )

    login_response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={
            "email_or_username": "test@example.com",
            "password": "testpassword123"
        }
    )
    token = login_response.json()["access_token"]
    refresh_token = login_response.json()["refresh_token"]

    # Logout
    response = client.post(
        f"{settings.API_V1_STR}/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
        json={"refresh_token": refresh_token}
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Successfully logged out"


@pytest.mark.asyncio
async def test_cleanup_expired_sessions(db_session: AsyncSession):
    """Test cleanup of expired sessions."""
    auth_service = AuthenticationService(db_session)

    # Register user
    user = await auth_service.register_user(
        email="test@example.com",
        password="testpassword123"
    )

    # Create expired session
    expired_session = UserSession(
        user_id=user.id,
        session_token="expired_token",
        refresh_token="expired_refresh",
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        is_active=True
    )
    db_session.add(expired_session)
    await db_session.commit()

    # Run cleanup
    cleaned_count = await auth_service.cleanup_expired_sessions()

    assert cleaned_count >= 1

    # Verify expired session is gone
    result = await db_session.execute(
        select(UserSession).where(UserSession.session_token == "expired_token")
    )
    session = result.scalar_one_or_none()
    assert session is None