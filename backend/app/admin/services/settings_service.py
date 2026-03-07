"""Admin service helpers for system settings."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.models import SystemSettings


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
                    description="Audio chunk size in MB / 音频切块大小(MB)",
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
                    description="Maximum concurrent processing threads / 最大并发处理线程数",
                    category="audio",
                )
            )

        await self.db.commit()

    async def _get_setting(self, key: str) -> SystemSettings | None:
        result = await self.db.execute(
            select(SystemSettings).where(SystemSettings.key == key)
        )
        return result.scalar_one_or_none()
