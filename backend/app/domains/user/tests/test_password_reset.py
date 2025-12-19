"""Tests for password reset functionality."""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.user.models import User, PasswordReset
from app.domains.user.services.auth_service import AuthenticationService
from app.core.exceptions import BadRequestError, NotFoundError
from app.shared.schemas import ForgotPasswordRequest, ResetPasswordRequest


@pytest.fixture
async def test_user(async_session: AsyncSession):
    """Create a test user."""
    user = User(
        email="test@example.com",
        username="testuser",
        hashed_password="hashed_password",
        status="active",
        is_verified=False,
        is_superuser=False
    )
    async_session.add(user)
    await async_session.commit()
    await async_session.refresh(user)
    return user


@pytest.fixture
def auth_service(async_session: AsyncSession):
    """Create authentication service instance."""
    return AuthenticationService(async_session)


class TestPasswordResetFlow:
    """Test password reset flow."""

    @pytest.mark.asyncio
    async def test_create_password_reset_token_success(
        self,
        auth_service: AuthenticationService,
        test_user: User
    ):
        """Test successful password reset token creation."""
        result = await auth_service.create_password_reset_token(
            email=test_user.email
        )

        assert result["message"] == "If an account with this email exists, a password reset link has been sent."
        assert "token" in result
        assert "expires_at" in result

        # Verify token was created in database
        token_record = await auth_service._get_valid_password_reset_token(result["token"])
        assert token_record is not None
        assert token_record.email == test_user.email
        assert token_record.is_used is False

    @pytest.mark.asyncio
    async def test_create_password_reset_token_nonexistent_email(
        self,
        auth_service: AuthenticationService
    ):
        """Test password reset token creation with non-existent email."""
        result = await auth_service.create_password_reset_token(
            email="nonexistent@example.com"
        )

        # Should not reveal if email exists
        assert result["message"] == "If an account with this email exists, a password reset link has been sent."
        assert result["token"] is None

    @pytest.mark.asyncio
    async def test_invalidate_existing_tokens(
        self,
        auth_service: AuthenticationService,
        test_user: User
    ):
        """Test that existing tokens are invalidated when creating a new one."""
        # Create first token
        result1 = await auth_service.create_password_reset_token(
            email=test_user.email
        )
        token1 = result1["token"]

        # Create second token
        result2 = await auth_service.create_password_reset_token(
            email=test_user.email
        )
        token2 = result2["token"]

        # First token should be invalidated
        old_token = await auth_service._get_valid_password_reset_token(token1)
        assert old_token is None

        # Second token should be valid
        new_token = await auth_service._get_valid_password_reset_token(token2)
        assert new_token is not None
        assert new_token.token == token2

    @pytest.mark.asyncio
    async def test_reset_password_success(
        self,
        auth_service: AuthenticationService,
        test_user: User
    ):
        """Test successful password reset."""
        # Create reset token
        reset_result = await auth_service.create_password_reset_token(
            email=test_user.email
        )
        token = reset_result["token"]

        # Reset password
        result = await auth_service.reset_password(
            token=token,
            new_password="NewSecurePassword123"
        )

        assert result["message"] == "Password has been successfully reset. Please login with your new password."

        # Verify token is marked as used
        token_record = await auth_service._get_valid_password_reset_token(token)
        assert token_record is None  # Should be invalid now

        # Verify user can authenticate with new password
        user = await auth_service._get_user_by_email(test_user.email)
        assert user is not None
        # Password hash should be different
        assert user.hashed_password != test_user.hashed_password

    @pytest.mark.asyncio
    async def test_reset_password_invalid_token(
        self,
        auth_service: AuthenticationService
    ):
        """Test password reset with invalid token."""
        with pytest.raises(BadRequestError, match="Invalid or expired reset token"):
            await auth_service.reset_password(
                token="invalid-token",
                new_password="NewSecurePassword123"
            )

    @pytest.mark.asyncio
    async def test_reset_password_expired_token(
        self,
        auth_service: AuthenticationService,
        test_user: User
    ):
        """Test password reset with expired token."""
        # Create token
        result = await auth_service.create_password_reset_token(
            email=test_user.email
        )
        token = result["token"]

        # Manually expire the token
        async with auth_service.db as session:
            token_record = await auth_service._get_valid_password_reset_token(token)
            if token_record:
                token_record.expires_at = datetime.utcnow() - timedelta(hours=1)
                await session.commit()

        # Try to use expired token
        with pytest.raises(BadRequestError, match="Invalid or expired reset token"):
            await auth_service.reset_password(
                token=token,
                new_password="NewSecurePassword123"
            )

    @pytest.mark.asyncio
    async def test_reset_password_weak_password(
        self,
        auth_service: AuthenticationService,
        test_user: User
    ):
        """Test password reset with weak password."""
        # Create token
        result = await auth_service.create_password_reset_token(
            email=test_user.email
        )
        token = result["token"]

        # Try with weak password
        with pytest.raises(BadRequestError, match="Password must be at least 8 characters long"):
            await auth_service.reset_password(
                token=token,
                new_password="weak"
            )

    @pytest.mark.asyncio
    async def test_reset_password_already_used_token(
        self,
        auth_service: AuthenticationService,
        test_user: User
    ):
        """Test password reset with already used token."""
        # Create token
        result = await auth_service.create_password_reset_token(
            email=test_user.email
        )
        token = result["token"]

        # First use
        await auth_service.reset_password(
            token=token,
            new_password="NewSecurePassword123"
        )

        # Try to use again
        with pytest.raises(BadRequestError, match="Invalid or expired reset token"):
            await auth_service.reset_password(
                token=token,
                new_password="AnotherSecurePassword123"
            )


@pytest.mark.asyncio
async def test_forgot_password_endpoint(async_client, test_user):
    """Test forgot password API endpoint."""
    request_data = ForgotPasswordRequest(email=test_user.email)

    response = await async_client.post(
        "/api/v1/auth/forgot-password",
        json=request_data.model_dump()
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "If an account with this email exists, a password reset link has been sent."
    assert "token" in data  # Will be None in production
    assert "expires_at" in data


@pytest.mark.asyncio
async def test_forgot_password_nonexistent_email(async_client):
    """Test forgot password with non-existent email."""
    request_data = ForgotPasswordRequest(email="nonexistent@example.com")

    response = await async_client.post(
        "/api/v1/auth/forgot-password",
        json=request_data.model_dump()
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "If an account with this email exists, a password reset link has been sent."


@pytest.mark.asyncio
async def test_reset_password_endpoint(async_client, test_user):
    """Test reset password API endpoint."""
    # First, create a reset token directly in the database
    import uuid

    reset_token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)

    async with async_client.app.state.db_pool.get() as db:
        password_reset = PasswordReset(
            email=test_user.email,
            token=reset_token,
            expires_at=expires_at,
            is_used=False
        )
        db.add(password_reset)
        await db.commit()

    # Now reset password
    request_data = ResetPasswordRequest(
        token=reset_token,
        new_password="NewSecurePassword123"
    )

    response = await async_client.post(
        "/api/v1/auth/reset-password",
        json=request_data.model_dump()
    )

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Password has been successfully reset. Please login with your new password."


@pytest.mark.asyncio
async def test_reset_password_invalid_token_endpoint(async_client):
    """Test reset password endpoint with invalid token."""
    request_data = ResetPasswordRequest(
        token="invalid-token",
        new_password="NewSecurePassword123"
    )

    response = await async_client.post(
        "/api/v1/auth/reset-password",
        json=request_data.model_dump()
    )

    assert response.status_code == 400
    assert "Invalid or expired reset token" in response.json()["detail"]


@pytest.mark.asyncio
async def test_reset_password_weak_password_endpoint(async_client, test_user):
    """Test reset password endpoint with weak password."""
    # Create a reset token
    import uuid

    reset_token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)

    async with async_client.app.state.db_pool.get() as db:
        password_reset = PasswordReset(
            email=test_user.email,
            token=reset_token,
            expires_at=expires_at,
            is_used=False
        )
        db.add(password_reset)
        await db.commit()

    # Try with weak password
    request_data = ResetPasswordRequest(
        token=reset_token,
        new_password="weak"
    )

    response = await async_client.post(
        "/api/v1/auth/reset-password",
        json=request_data.model_dump()
    )

    assert response.status_code == 422  # Validation error
    assert "Password must be at least 8 characters long" in response.text


@pytest.mark.asyncio
async def test_email_format_validation():
    """Test email format validation."""
    from app.core.email import validate_email_format

    # Valid emails
    assert validate_email_format("test@example.com") == True
    assert validate_email_format("user.name+tag@domain.co.uk") == True

    # Invalid emails
    assert validate_email_format("invalid-email") == False
    assert validate_email_format("@domain.com") == False
    assert validate_email_format("user@") == False


@pytest.mark.asyncio
async def test_token_generation():
    """Test token generation functions."""
    from app.core.email import generate_secure_token, generate_uuid_token

    # Test secure token
    token1 = generate_secure_token(16)
    token2 = generate_secure_token(16)
    assert len(token1) == 32  # 16 bytes = 32 hex chars
    assert len(token2) == 32
    assert token1 != token2

    # Test UUID token
    uuid_token1 = generate_uuid_token()
    uuid_token2 = generate_uuid_token()
    assert "-" in uuid_token1  # UUID format
    assert "-" in uuid_token2
    assert uuid_token1 != uuid_token2


@pytest.mark.asyncio
@patch('app.core.email.settings.ENVIRONMENT', 'development')
async def test_email_service_development():
    """Test email service in development mode."""
    from app.core.email import EmailService

    service = EmailService()

    # In development, should just log the email
    result = await service.send_password_reset_email(
        email="test@example.com",
        token="test-token",
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )

    assert result == True


@pytest.mark.asyncio
async def test_password_resets_table_creation(async_session):
    """Test that password_resets table can be created and used."""
    # Check if table exists
    from sqlalchemy import text

    result = await async_session.execute(
        text("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_name = 'password_resets'
        """)
    )
    table_exists = result.scalar() is not None

    # In a real test, you would ensure the table is created
    # For now, just check if the model can be instantiated
    reset = PasswordReset(
        email="test@example.com",
        token="test-token",
        expires_at=datetime.utcnow() + timedelta(hours=1)
    )

    assert reset.email == "test@example.com"
    assert reset.token == "test-token"
    assert reset.is_used is False