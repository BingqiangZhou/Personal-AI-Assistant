from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.admin.routes.users_audit import reset_user_password, toggle_user
from app.domains.user.models import UserStatus


def _build_request() -> Mock:
    request = Mock()
    request.client = Mock(host="127.0.0.1")
    request.headers = {"user-agent": "pytest"}
    return request


def _db_result(value):
    result = Mock()
    result.scalar_one_or_none.return_value = value
    return result


@pytest.mark.asyncio
async def test_toggle_user_uses_audit_module_without_deleted_helper():
    db = AsyncMock()
    admin_user = Mock(id=1, username="admin")
    target_user = Mock(id=2, username="target", status=UserStatus.ACTIVE)
    db.execute.return_value = _db_result(target_user)

    with patch("app.admin.routes.users_audit.log_admin_action", new=AsyncMock()) as audit:
        response = await toggle_user(
            user_id=2,
            request=_build_request(),
            user=admin_user,
            db=db,
        )

    assert response.status_code == 200
    assert target_user.status == UserStatus.INACTIVE
    audit.assert_awaited_once()


@pytest.mark.asyncio
async def test_reset_password_uses_audit_module_without_deleted_helper():
    db = AsyncMock()
    admin_user = Mock(id=1, username="admin")
    target_user = Mock(id=2, username="target")
    db.execute.return_value = _db_result(target_user)

    with patch("app.admin.routes.users_audit.log_admin_action", new=AsyncMock()) as audit:
        response = await reset_user_password(
            user_id=2,
            request=_build_request(),
            user=admin_user,
            db=db,
        )

    assert response.status_code == 200
    audit.assert_awaited_once()
