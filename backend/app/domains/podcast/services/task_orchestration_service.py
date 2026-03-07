"""Thin coordinator for Celery/task orchestration services."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.integration.secure_rss_parser import SecureRSSParser
from app.domains.podcast.repositories import PodcastSubscriptionRepository
from app.domains.podcast.services.sync_service import PodcastSyncService
from app.domains.podcast.services.task_feed_sync_service import (
    PodcastTaskFeedSyncService,
)
from app.domains.podcast.services.task_maintenance_service import (
    PodcastTaskMaintenanceService,
)
from app.domains.podcast.services.task_reporting_service import (
    PodcastTaskReportingService,
)
from app.domains.podcast.services.task_transcription_orchestration_service import (
    PodcastTaskTranscriptionOrchestrationService,
)


class PodcastTaskOrchestrationService:
    """Compose narrow task orchestration collaborators."""

    def __init__(self, session: AsyncSession):
        self.session = session

    def _transcription(self) -> PodcastTaskTranscriptionOrchestrationService:
        return PodcastTaskTranscriptionOrchestrationService(self.session)

    def _feed_sync(self) -> PodcastTaskFeedSyncService:
        return PodcastTaskFeedSyncService(
            self.session,
            repo_factory=PodcastSubscriptionRepository,
            parser_factory=SecureRSSParser,
            sync_service_factory=PodcastSyncService,
        )

    def _reporting(self) -> PodcastTaskReportingService:
        return PodcastTaskReportingService(self.session)

    def _maintenance(self) -> PodcastTaskMaintenanceService:
        return PodcastTaskMaintenanceService(self.session)

    async def process_audio_transcription_task(self, **kwargs):
        return await self._transcription().process_audio_transcription_task(**kwargs)

    async def trigger_episode_transcription_pipeline(self, **kwargs):
        return await self._transcription().trigger_episode_transcription_pipeline(
            **kwargs
        )

    async def refresh_all_podcast_feeds(self):
        return await self._feed_sync().refresh_all_podcast_feeds()

    async def process_opml_subscription_episodes(self, **kwargs):
        return await self._feed_sync().process_opml_subscription_episodes(**kwargs)

    def enqueue_opml_subscription_episodes(self, **kwargs) -> Any:
        """Queue OPML episode parsing without exposing Celery task imports."""
        from app.domains.podcast.tasks.opml_import import (
            process_opml_subscription_episodes,
        )

        return process_opml_subscription_episodes.delay(**kwargs)

    def enqueue_audio_transcription(
        self,
        task_id: int,
        config_db_id: int | None = None,
    ) -> Any:
        """Queue a transcription worker task without exposing Celery imports."""
        from app.domains.podcast.tasks.transcription import process_audio_transcription

        return process_audio_transcription.delay(task_id, config_db_id)

    def enqueue_episode_processing(
        self,
        episode_id: int,
        user_id: int,
    ) -> Any:
        """Queue the episode transcription/summary pipeline."""
        from app.domains.podcast.tasks.transcription import (
            process_podcast_episode_with_transcription,
        )

        return process_podcast_episode_with_transcription.delay(episode_id, user_id)

    async def generate_daily_reports(self, **kwargs):
        return await self._reporting().generate_daily_reports(**kwargs)

    async def get_task_statistics(self):
        return await self._maintenance().get_task_statistics()

    async def log_periodic_task_statistics(self):
        return await self._maintenance().log_periodic_task_statistics()

    async def cleanup_old_playback_states(self):
        return await self._maintenance().cleanup_old_playback_states()

    async def cleanup_old_transcription_temp_files(self, **kwargs):
        return await self._maintenance().cleanup_old_transcription_temp_files(**kwargs)

    async def auto_cleanup_cache_files(self):
        return await self._maintenance().auto_cleanup_cache_files()

    async def process_pending_transcriptions(self):
        return await self._maintenance().process_pending_transcriptions()

    async def generate_podcast_recommendations(self):
        return await self._maintenance().generate_podcast_recommendations()
