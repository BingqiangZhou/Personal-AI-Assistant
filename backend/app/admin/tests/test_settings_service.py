from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.admin.services import settings_service as settings_service_module
from app.admin.services.settings_service import AdminSettingsService


def test_validate_audio_settings_accepts_supported_range():
    service = AdminSettingsService(db=AsyncMock())

    service.validate_audio_settings(
        chunk_size_mb=10,
        max_concurrent_threads=4,
    )


@pytest.mark.parametrize(
    ("chunk_size_mb", "max_concurrent_threads", "message"),
    [
        (4, 4, "chunk_size_mb must be between 5 and 25"),
        (26, 4, "chunk_size_mb must be between 5 and 25"),
        (10, 0, "max_concurrent_threads must be between 1 and 16"),
        (10, 17, "max_concurrent_threads must be between 1 and 16"),
    ],
)
def test_validate_audio_settings_rejects_invalid_values(
    chunk_size_mb: int,
    max_concurrent_threads: int,
    message: str,
):
    service = AdminSettingsService(db=AsyncMock())

    with pytest.raises(HTTPException) as exc_info:
        service.validate_audio_settings(
            chunk_size_mb=chunk_size_mb,
            max_concurrent_threads=max_concurrent_threads,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == message


def test_validate_frequency_settings_accepts_valid_weekly_payload():
    service = AdminSettingsService(db=AsyncMock())

    service.validate_frequency_settings(
        update_frequency="WEEKLY",
        update_time="09:30",
        update_day=3,
    )


@pytest.mark.parametrize(
    ("update_frequency", "update_time", "update_day", "message"),
    [
        (
            "MONTHLY",
            "09:30",
            3,
            "Invalid frequency. Must be one of: ['HOURLY', 'DAILY', 'WEEKLY']",
        ),
        (
            "DAILY",
            None,
            None,
            "update_time is required for DAILY and WEEKLY frequencies",
        ),
        (
            "WEEKLY",
            "09:30",
            None,
            "update_day is required for WEEKLY frequency",
        ),
        (
            "WEEKLY",
            "09:30",
            9,
            "update_day must be between 1 and 7",
        ),
        (
            "DAILY",
            "24:00",
            None,
            "update_time must use HH:MM format",
        ),
    ],
)
def test_validate_frequency_settings_rejects_invalid_values(
    update_frequency: str,
    update_time: str | None,
    update_day: int | None,
    message: str,
):
    service = AdminSettingsService(db=AsyncMock())

    with pytest.raises(HTTPException) as exc_info:
        service.validate_frequency_settings(
            update_frequency=update_frequency,
            update_time=update_time,
            update_day=update_day,
        )

    assert exc_info.value.status_code == 400
    assert exc_info.value.detail == message


@pytest.mark.asyncio
async def test_save_audio_settings_validates_persists_and_audits(monkeypatch: pytest.MonkeyPatch):
    service = AdminSettingsService(db=AsyncMock())
    service.update_audio_settings = AsyncMock()
    audit_mock = AsyncMock()
    monkeypatch.setattr(settings_service_module, "log_admin_action", audit_mock)

    payload = await service.save_audio_settings(
        request=object(),
        user=SimpleNamespace(id=7, username="admin"),
        chunk_size_mb=12,
        max_concurrent_threads=3,
    )

    service.update_audio_settings.assert_awaited_once_with(
        chunk_size_mb=12,
        max_concurrent_threads=3,
    )
    audit_mock.assert_awaited_once()
    assert payload == {"success": True, "message": "Settings saved"}


@pytest.mark.asyncio
async def test_save_frequency_settings_returns_compatible_success_message(monkeypatch: pytest.MonkeyPatch):
    service = AdminSettingsService(db=AsyncMock())
    service.update_frequency_settings = AsyncMock(
        return_value=({"update_frequency": "DAILY"}, 5)
    )
    audit_mock = AsyncMock()
    monkeypatch.setattr(settings_service_module, "log_admin_action", audit_mock)

    payload = await service.save_frequency_settings(
        request=object(),
        user=SimpleNamespace(id=8, username="root"),
        update_frequency="DAILY",
        update_time="09:15",
        update_day=None,
    )

    service.update_frequency_settings.assert_awaited_once_with(
        update_frequency="DAILY",
        update_time="09:15",
        update_day=None,
    )
    audit_mock.assert_awaited_once()
    assert payload == {
        "success": True,
        "message": "RSS settings saved (updated 5 user-subscription mappings)",
    }


@pytest.mark.asyncio
async def test_save_cleanup_config_skips_audit_when_update_fails(monkeypatch: pytest.MonkeyPatch):
    service = AdminSettingsService(db=AsyncMock())
    service.update_cleanup_config = AsyncMock(return_value={"success": False, "message": "noop"})
    audit_mock = AsyncMock()
    monkeypatch.setattr(settings_service_module, "log_admin_action", audit_mock)

    payload = await service.save_cleanup_config(
        request=object(),
        user=SimpleNamespace(id=9, username="ops"),
        enabled=False,
    )

    service.update_cleanup_config.assert_awaited_once_with(False)
    audit_mock.assert_not_awaited()
    assert payload == {"success": False, "message": "noop"}


@pytest.mark.asyncio
async def test_run_cleanup_logs_cleanup_summary(monkeypatch: pytest.MonkeyPatch):
    service = AdminSettingsService(db=AsyncMock())
    service.execute_cleanup = AsyncMock(
        return_value={
            "total": {
                "deleted_count": 4,
                "freed_space_human": "128 MB",
            }
        }
    )
    audit_mock = AsyncMock()
    monkeypatch.setattr(settings_service_module, "log_admin_action", audit_mock)

    payload = await service.run_cleanup(
        request=object(),
        user=SimpleNamespace(id=10, username="maint"),
        keep_days=2,
    )

    service.execute_cleanup.assert_awaited_once_with(2)
    audit_mock.assert_awaited_once()
    assert payload["total"]["deleted_count"] == 4