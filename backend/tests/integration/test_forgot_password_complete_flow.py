"""Integration tests for complete forgot password flow."""

import pytest
import json
from datetime import datetime, timedelta
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.domains.user.models import User, PasswordReset
from app.core.security import verify_password


class TestForgotPasswordCompleteFlow:
    """Test complete forgot password flow from API to database."""

    @pytest.mark.asyncio
    async def test_complete_flow_forgot_to_reset_password(
        self,
        async_client: AsyncClient,
        async_session: AsyncSession
    ):
        """Test complete flow: forgot password -> reset password -> login with new password."""

        # 1. Register a test user first
        register_data = {
            "email": "testforgot@example.com",
            "username": "testforgot",
            "password": "OriginalPassword123"
        }

        response = await async_client.post("/api/v1/auth/register", json=register_data)
        assert response.status_code == 201
        register_result = response.json()
        assert "access_token" in register_result

        # 2. Request password reset
        forgot_data = {
            "email": "testforgot@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=forgot_data)
        assert response.status_code == 200
        forgot_result = response.json()

        # Verify response structure
        assert "message" in forgot_result
        assert "token" in forgot_result
        assert "expires_at" in forgot_result
        assert forgot_result["message"] == "If an account with this email exists, a password reset link has been sent."

        # Get the token for testing (in development mode)
        reset_token = forgot_result["token"]
        assert reset_token is not None

        # 3. Verify token was created in database
        result = await async_session.execute(
            text("SELECT * FROM password_resets WHERE token = :token"),
            {"token": reset_token}
        )
        token_record = result.fetchone()
        assert token_record is not None
        assert token_record.email == "testforgot@example.com"
        assert token_record.is_used is False

        # 4. Reset password with the token
        reset_data = {
            "token": reset_token,
            "new_password": "NewSecurePassword456"
        }

        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 200
        reset_result = response.json()
        assert reset_result["message"] == "Password has been successfully reset. Please login with your new password."

        # 5. Verify token is marked as used
        result = await async_session.execute(
            text("SELECT * FROM password_resets WHERE token = :token"),
            {"token": reset_token}
        )
        token_record = result.fetchone()
        assert token_record.is_used is True

        # 6. Verify login with old password fails
        login_old_data = {
            "email_or_username": "testforgot@example.com",
            "password": "OriginalPassword123"
        }

        response = await async_client.post("/api/v1/auth/login", json=login_old_data)
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

        # 7. Verify login with new password succeeds
        login_new_data = {
            "email_or_username": "testforgot@example.com",
            "password": "NewSecurePassword456"
        }

        response = await async_client.post("/api/v1/auth/login", json=login_new_data)
        assert response.status_code == 200
        login_result = response.json()
        assert "access_token" in login_result
        assert "refresh_token" in login_result

    @pytest.mark.asyncio
    async def test_forgot_password_security_consistency(
        self,
        async_client: AsyncClient,
        async_session: AsyncSession
    ):
        """Test that forgot password response is consistent for existing and non-existing emails."""

        # Test with existing email
        # First create a user
        register_data = {
            "email": "existing@example.com",
            "username": "existinguser",
            "password": "Password123"
        }

        await async_client.post("/api/v1/auth/register", json=register_data)

        # Request password reset for existing email
        forgot_existing = {
            "email": "existing@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=forgot_existing)
        assert response.status_code == 200
        existing_result = response.json()

        # Request password reset for non-existing email
        forgot_nonexisting = {
            "email": "nonexisting@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=forgot_nonexisting)
        assert response.status_code == 200
        nonexisting_result = response.json()

        # Responses should be identical
        assert existing_result["message"] == nonexisting_result["message"]
        assert existing_result["message"] == "If an account with this email exists, a password reset link has been sent."

        # Only existing email should have a token in development mode
        assert existing_result["token"] is not None
        assert nonexisting_result["token"] is None

    @pytest.mark.asyncio
    async def test_multiple_reset_requests_invalidate_old_tokens(
        self,
        async_client: AsyncClient,
        async_session: AsyncSession
    ):
        """Test that multiple reset requests invalidate previous tokens."""

        # Create a user
        register_data = {
            "email": "multireset@example.com",
            "username": "multireset",
            "password": "Password123"
        }

        await async_client.post("/api/v1/auth/register", json=register_data)

        # First reset request
        first_reset = {
            "email": "multireset@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=first_reset)
        assert response.status_code == 200
        first_token = response.json()["token"]

        # Second reset request
        second_reset = {
            "email": "multireset@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=second_reset)
        assert response.status_code == 200
        second_token = response.json()["token"]

        # Tokens should be different
        assert first_token != second_token

        # First token should be invalidated
        reset_data = {
            "token": first_token,
            "new_password": "NewPassword123"
        }

        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 400
        assert "Invalid or expired reset token" in response.json()["detail"]

        # Second token should work
        reset_data["token"] = second_token
        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_reset_password_validation_errors(
        self,
        async_client: AsyncClient
    ):
        """Test various validation errors in reset password."""

        # Test missing token
        reset_data = {
            "new_password": "ValidPassword123"
        }

        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 422  # Validation error

        # Test missing password
        reset_data = {
            "token": "some-token"
        }

        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 422  # Validation error

        # Test short password
        reset_data = {
            "token": "some-token",
            "new_password": "123"
        }

        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_forgot_password_edge_cases(
        self,
        async_client: AsyncClient
    ):
        """Test edge cases for forgot password endpoint."""

        # Test with empty email
        response = await async_client.post("/api/v1/auth/forgot-password", json={"email": ""})
        assert response.status_code == 422  # Validation error

        # Test with invalid email format
        response = await async_client.post("/api/v1/auth/forgot-password", json={"email": "invalid-email"})
        assert response.status_code == 422  # Validation error

        # Test with missing email field
        response = await async_client.post("/api/v1/auth/forgot-password", json={})
        assert response.status_code == 422  # Validation error

    @pytest.mark.asyncio
    async def test_reset_password_with_uppercase_email(
        self,
        async_client: AsyncClient,
        async_session: AsyncSession
    ):
        """Test password reset with uppercase email (case insensitive)."""

        # Create user with lowercase email
        register_data = {
            "email": "case sensitive@example.com",
            "username": "casesensitive",
            "password": "Password123"
        }

        await async_client.post("/api/v1/auth/register", json=register_data)

        # Request reset with uppercase email
        forgot_data = {
            "email": "CASE SENSITIVE@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=forgot_data)
        assert response.status_code == 200
        result = response.json()

        # Should still work and return token
        assert result["token"] is not None

    @pytest.mark.asyncio
    async def test_reset_password_token_expiry(
        self,
        async_client: AsyncClient,
        async_session: AsyncSession
    ):
        """Test that expired tokens cannot be used."""

        # Create a user
        register_data = {
            "email": "expiretest@example.com",
            "username": "expiretest",
            "password": "Password123"
        }

        await async_client.post("/api/v1/auth/register", json=register_data)

        # Request password reset
        forgot_data = {
            "email": "expiretest@example.com"
        }

        response = await async_client.post("/api/v1/auth/forgot-password", json=forgot_data)
        token = response.json()["token"]

        # Manually expire the token in database
        expired_time = datetime.utcnow() - timedelta(hours=1)
        await async_session.execute(
            text("UPDATE password_resets SET expires_at = :expires_at WHERE token = :token"),
            {"expires_at": expired_time, "token": token}
        )
        await async_session.commit()

        # Try to use expired token
        reset_data = {
            "token": token,
            "new_password": "NewPassword123"
        }

        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 400
        assert "Invalid or expired reset token" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_concurrent_reset_requests(
        self,
        async_client: AsyncClient,
        async_session: AsyncSession
    ):
        """Test handling of concurrent reset requests."""

        # Create a user
        register_data = {
            "email": "concurrent@example.com",
            "username": "concurrent",
            "password": "Password123"
        }

        await async_client.post("/api/v1/auth/register", json=register_data)

        # Send multiple concurrent requests
        import asyncio

        forgot_data = {"email": "concurrent@example.com"}
        tasks = [
            async_client.post("/api/v1/auth/forgot-password", json=forgot_data)
            for _ in range(5)
        ]

        responses = await asyncio.gather(*tasks)

        # All should succeed
        for response in responses:
            assert response.status_code == 200
            result = response.json()
            assert result["message"] == "If an account with this email exists, a password reset link has been sent."

        # Check that only the last token is valid
        tokens = [r.json()["token"] for r in responses if r.json()["token"]]

        # All but the first should be valid (since each new request invalidates previous)
        for i, token in enumerate(tokens[:-1]):
            reset_data = {
                "token": token,
                "new_password": f"Password{i}123"
            }
            response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
            assert response.status_code == 400  # Should be invalidated

        # Last token should work
        reset_data = {
            "token": tokens[-1],
            "new_password": "FinalPassword123"
        }
        response = await async_client.post("/api/v1/auth/reset-password", json=reset_data)
        assert response.status_code == 200