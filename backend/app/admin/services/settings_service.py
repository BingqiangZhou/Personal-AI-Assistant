"""Admin service helpers for system settings."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.models import SystemSettings
from app.admin.storage_service import StorageCleanupService
from app.domains.subscription.models import (
    Subscription,
    UpdateFrequency,
    UserSubscription,
)


class AdminSettingsService:
    """Read and write admin-configurable system settings."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_audio_settings(self) -> dict[str, int]:
        """Return persisted audio-processing settings with defaults."""
        chunk_size_setting = await self._get_setting("audio.chunk_size_mb")
        threads_setting = await self._get_setting("audio.max_concurrent_threads")

        chunk_size_mb = 10
        max_concurrent_threads = 2

        if chunk_size_setting and chunk_size_setting.value:
            chunk_size_mb = chunk_size_setting.value.get("value", 10)
        if threads_setting and threads_setting.value:
            max_concurrent_threads = threads_setting.value.get("value", 2)

        return {
            "chunk_size_mb": chunk_size_mb,
            "max_concurrent_threads": max_concurrent_threads,
        }

    async def update_audio_settings(
        self,
        *,
        chunk_size_mb: int,
        max_concurrent_threads: int,
    ) -> None:
        """Persist audio-processing settings."""
        chunk_size_setting = await self._get_setting("audio.chunk_size_mb")
        if chunk_size_setting:
            chunk_size_setting.value = {"value": chunk_size_mb, "min": 5, "max": 25}
        else:
            self.db.add(
                SystemSettings(
                    key="audio.chunk_size_mb",
                    value={"value": chunk_size_mb, "min": 5, "max": 25},
                    description="Audio chunk size in MB / 闊抽鍒囧潡澶у皬(MB)",
                    category="audio",
                )
            )

        threads_setting = await self._get_setting("audio.max_concurrent_threads")
        if threads_setting:
            threads_setting.value = {
                "value": max_concurrent_threads,
                "min": 1,
                "max": 16,
            }
        else:
            self.db.add(
                SystemSettings(
                    key="audio.max_concurrent_threads",
                    value={"value": max_concurrent_threads, "min": 1, "max": 16},
                    description="Maximum concurrent processing threads / 鏈€澶у苟鍙戝鐞嗙嚎绋嬫暟",
                    category="audio",
                )
            )

        await self.db.commit()

    async def get_frequency_settings(self) -> dict[str, object]:
        """Return RSS subscription frequency settings with fallback source."""
        default_frequency = UpdateFrequency.HOURLY.value
        default_update_time = "00:00"
        default_day_of_week = 1
        source = "default"

        setting = await self._get_setting("rss.frequency_settings")
        if setting and setting.value:
            default_frequency = setting.value.get(
                "update_frequency", UpdateFrequency.HOURLY.value
            )
            default_update_time = setting.value.get("update_time", "00:00")
            default_day_of_week = setting.value.get("update_day_of_week", 1)
            source = "database"
        else:
            recent_result = await self.db.execute(
                select(
                    UserSubscription.update_frequency,
                    UserSubscription.update_time,
                    UserSubscription.update_day_of_week,
                )
                .where(UserSubscription.update_frequency.isnot(None))
                .group_by(
                    UserSubscription.update_frequency,
                    UserSubscription.update_time,
                    UserSubscription.update_day_of_week,
                )
                .order_by(func.count().desc())
                .limit(1)
            )
            row = recent_result.first()
            if row:
                default_frequency = row[0]
                default_update_time = row[1] or "00:00"
                default_day_of_week = row[2] or 1
                source = "user_subscription"

        return {
            "update_frequency": default_frequency,
            "update_time": default_update_time,
            "update_day_of_week": default_day_of_week,
            "source": source,
        }

    async def update_frequency_settings(
        self,
        *,
        update_frequency: str,
        update_time: str | None,
        update_day: int | None,
    ) -> tuple[dict[str, object], int]:
        """Persist RSS frequency settings and fan out to user mappings."""
        settings_data = {
            "update_frequency": update_frequency,
            "update_time": update_time if update_frequency in ["DAILY", "WEEKLY"] else None,
            "update_day_of_week": update_day if update_frequency == "WEEKLY" else None,
        }

        setting = await self._get_setting("rss.frequency_settings")
        if setting:
            setting.value = settings_data
        else:
            self.db.add(
                SystemSettings(
                    key="rss.frequency_settings",
                    value=settings_data,
                    description="RSS subscription update frequency settings",
                    category="subscription",
                )
            )

        user_subscriptions = (
            await self.db.execute(
                select(UserSubscription)
                .join(Subscription, Subscription.id == UserSubscription.subscription_id)
                .where(Subscription.source_type.in_(["rss", "podcast-rss"]))
            )
        ).scalars().all()

        total_count = 0
        for user_sub in user_subscriptions:
            user_sub.update_frequency = settings_data["update_frequency"]
            user_sub.update_time = settings_data["update_time"]
            user_sub.update_day_of_week = settings_data["update_day_of_week"]
            total_count += 1

        await self.db.commit()
        return settings_data, total_count

    async def get_security_settings(self) -> dict[str, object]:
        """Return current admin 2FA setting and source."""
        from app.admin.security_settings import get_admin_2fa_enabled

        admin_2fa_enabled, source = await get_admin_2fa_enabled(self.db)
        return {
            "admin_2fa_enabled": admin_2fa_enabled,
            "source": source,
        }

    async def update_security_settings(self, *, admin_2fa_enabled: bool) -> None:
        """Persist admin 2FA setting."""
        from app.admin.security_settings import set_admin_2fa_enabled

        await set_admin_2fa_enabled(self.db, admin_2fa_enabled)

    async def get_storage_info(self) -> dict:
        """Return storage usage information."""
        return await StorageCleanupService(self.db).get_storage_info()

    async def get_cleanup_config(self) -> dict:
        """Return automatic cleanup configuration."""
        return await StorageCleanupService(self.db).get_cleanup_config()

    async def update_cleanup_config(self, enabled: bool) -> dict:
        """Persist automatic cleanup configuration."""
        return await StorageCleanupService(self.db).update_cleanup_config(enabled)

    async def execute_cleanup(self, keep_days: int) -> dict:
        """Execute storage cleanup immediately."""
        return await StorageCleanupService(self.db).execute_cleanup(keep_days)

    async def _get_setting(self, key: str) -> SystemSettings | None:
        result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.key == key)
        )
        return result.scalar_one_or_none()
