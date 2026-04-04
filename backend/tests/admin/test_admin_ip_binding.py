"""Tests for admin session IP binding security."""

import inspect

import pytest

from app.admin.auth import (
    SESSION_TIMEOUT,
    _get_serializer,
    create_admin_session,
)


class TestCreateAdminSessionIncludesIP:
    """Verify create_admin_session embeds client_ip in the signed payload."""

    def test_session_contains_client_ip(self) -> None:
        token = create_admin_session(user_id=1, client_ip="192.168.1.100")
        data = _get_serializer().loads(token, max_age=SESSION_TIMEOUT)
        assert data["client_ip"] == "192.168.1.100"
        assert data["user_id"] == 1

    def test_session_different_ips_produce_different_tokens(self) -> None:
        token_a = create_admin_session(user_id=1, client_ip="10.0.0.1")
        token_b = create_admin_session(user_id=1, client_ip="10.0.0.2")
        assert token_a != token_b

    def test_session_preserves_all_fields(self) -> None:
        token = create_admin_session(user_id=42, client_ip="::1")
        data = _get_serializer().loads(token, max_age=SESSION_TIMEOUT)
        assert data["user_id"] == 42
        assert data["client_ip"] == "::1"
        assert "created_at" in data


class TestIPValidationLogic:
    """Verify the IP mismatch detection in AdminAuthRequired."""

    @pytest.mark.asyncio
    async def test_ip_mismatch_raises_401(self) -> None:
        """A token bound to one IP should be rejected when presented from a different IP."""
        from unittest.mock import AsyncMock, MagicMock

        from app.admin.auth import AdminAuthRequired

        # Build a valid session token bound to 10.0.0.1
        token = create_admin_session(user_id=1, client_ip="10.0.0.1")

        # Fake request coming from a different IP
        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.99"
        mock_request.cookies = {"admin_session": token}

        # Mock DB session that should never be reached (IP check comes first)
        mock_db = AsyncMock()

        dep = AdminAuthRequired(require_2fa=True)

        with pytest.raises(Exception) as exc_info:
            await dep.__call__(request=mock_request, admin_session=token, db=mock_db)

        # The raised exception should be an HTTPException with 401
        assert exc_info.value.status_code == 401
        assert "IP mismatch" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_ip_match_passes_validation(self) -> None:
        """A token presented from the same IP should pass the IP check."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.admin.auth import AdminAuthRequired
        from app.domains.user.models import User

        token = create_admin_session(user_id=1, client_ip="10.0.0.1")

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"

        # Build a mock user for the DB lookup
        mock_user = MagicMock(spec=User)
        mock_user.is_active = True
        mock_user.is_2fa_enabled = True

        mock_repo = AsyncMock()
        mock_repo.get_by_id.return_value = mock_user

        mock_db = AsyncMock()

        dep = AdminAuthRequired(require_2fa=True)

        with (
            patch("app.admin.auth.UserRepository", return_value=mock_repo),
            # get_admin_2fa_enabled is imported locally inside __call__,
            # so patch it at its source module.
            patch(
                "app.admin.security_settings.get_admin_2fa_enabled",
                return_value=(True, None),
            ),
        ):
            result = await dep.__call__(
                request=mock_request, admin_session=token, db=mock_db
            )

        assert result == mock_user


class TestNoInternalErrorLeak:
    """Verify error responses do not expose internal exception details."""

    def test_generic_exception_uses_generic_message(self) -> None:
        """Static analysis: the catch-all handler should not embed the exception in detail."""
        from app.admin import auth as auth_module

        source = inspect.getsource(auth_module)
        # The old code had: detail=f"Authentication error: {err}"
        # The new code should use: detail="Authentication failed"
        assert 'f"Authentication error:' not in source
        assert "Authentication failed" in source

    @pytest.mark.asyncio
    async def test_unexpected_error_returns_generic_message(self) -> None:
        """When an unexpected exception occurs, only a generic message is returned."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.admin.auth import AdminAuthRequired

        token = create_admin_session(user_id=1, client_ip="10.0.0.1")

        mock_request = MagicMock()
        mock_request.client.host = "10.0.0.1"

        # Make loads() raise an unexpected error
        mock_db = AsyncMock()

        dep = AdminAuthRequired(require_2fa=True)

        with patch(
            "app.admin.auth._get_serializer",
            side_effect=RuntimeError("database connection pool exhausted"),
        ), pytest.raises(Exception) as exc_info:
            await dep.__call__(
                request=mock_request, admin_session=token, db=mock_db
            )

        assert exc_info.value.status_code == 500
        # Must NOT contain the internal error message
        assert "database connection pool exhausted" not in exc_info.value.detail
        assert exc_info.value.detail == "Authentication failed"
