"""Podcast background task orchestration service -- thin facade.

Delegates to four focused orchestrators in the ``orchestration`` package:
- FeedSyncOrchestrator      -- RSS feed refresh and OPML parsing
- TranscriptionOrchestrator -- transcription dispatch and execution
- ReportOrchestrator        -- daily report generation
- MaintenanceOrchestrator   -- statistics, cleanup, housekeeping

The public API is preserved so that all Celery task handlers and tests
continue to import ``PodcastTaskOrchestrationService`` unchanged.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import worker_db_session  # noqa: F401
from app.core.redis import get_shared_redis

# Re-export names that tests patch at this module path.
from app.domains.podcast.integration.secure_rss_parser import (
    SecureRSSParser,  # noqa: F401
)
from app.domains.podcast.repositories import PodcastSubscriptionRepository  # noqa: F401
from app.domains.podcast.services.orchestration.feed_sync import FeedSyncOrchestrator
from app.domains.podcast.services.orchestration.maintenance import (
    MaintenanceOrchestrator,
)
from app.domains.podcast.services.orchestration.report import ReportOrchestrator
from app.domains.podcast.services.orchestration.transcription import (
    TranscriptionOrchestrator,
)
from app.domains.podcast.services.transcription_workflow_service import (  # noqa: F401
    TranscriptionWorkflowService,
)


logger = logging.getLogger(__name__)


class PodcastTaskOrchestrationService:
    """Facade that delegates to four focused orchestrators.

    All public methods forward to the corresponding orchestrator so that
    existing Celery task handler imports remain unchanged.
    """

    _refresh_batch_size = 100  # preserved for test compatibility

    def __init__(self, session: AsyncSession):
        self.session = session
        self.redis = get_shared_redis()
        self._feed_sync = FeedSyncOrchestrator(session)
        self._transcription = TranscriptionOrchestrator(session)
        self._report = ReportOrchestrator(session)
        self._maintenance = MaintenanceOrchestrator(session)

    # ── Feed sync ──────────────────────────────────────────────────────────

    async def refresh_all_podcast_feeds(self) -> dict:
        return await self._feed_sync.refresh_all_podcast_feeds()

    async def _load_due_refresh_candidates(self, **kwargs):
        return await self._feed_sync._load_due_refresh_candidates(**kwargs)

    async def process_opml_subscription_episodes(self, **kwargs) -> dict:
        return await self._feed_sync.process_opml_subscription_episodes(**kwargs)

    # ── Transcription orchestration ────────────────────────────────────────

    async def process_audio_transcription_task(self, **kwargs) -> dict:
        return await self._transcription.process_audio_transcription_task(**kwargs)

    async def trigger_episode_transcription_pipeline(self, **kwargs) -> dict:
        return await self._transcription.trigger_episode_transcription_pipeline(
            **kwargs,
        )

    def _build_transcription_workflow(self):
        return self._transcription.build_transcription_workflow()

    # ── Reporting ──────────────────────────────────────────────────────────

    async def generate_daily_reports(self, **kwargs) -> dict:
        return await self._report.generate_daily_reports(**kwargs)

    # ── Maintenance ────────────────────────────────────────────────────────

    async def get_task_statistics(self) -> dict:
        return await self._maintenance.get_task_statistics()

    async def log_periodic_task_statistics(self) -> dict:
        return await self._maintenance.log_periodic_task_statistics()

    async def cleanup_old_playback_states(self) -> dict:
        return await self._maintenance.cleanup_old_playback_states()

    async def cleanup_old_transcription_temp_files(self, **kwargs) -> dict:
        return await self._maintenance.cleanup_old_transcription_temp_files(**kwargs)

    async def auto_cleanup_cache_files(self) -> dict:
        return await self._maintenance.auto_cleanup_cache_files()

    async def process_pending_transcriptions(self) -> dict:
        return await self._transcription.process_pending_transcriptions()

    # ── Celery task enqueue helpers ────────────────────────────────────────

    def enqueue_opml_subscription_episodes(self, **kwargs) -> Any:
        return self._maintenance.enqueue_opml_subscription_episodes(**kwargs)

    def enqueue_audio_transcription(
        self,
        task_id: int,
        config_db_id: int | None = None,
    ) -> Any:
        return self._transcription.enqueue_audio_transcription(
            task_id,
            config_db_id,
        )

    def enqueue_episode_processing(self, **kwargs) -> Any:
        return self._transcription.enqueue_episode_processing(**kwargs)

    # ── Shared utilities (preserved for test monkeypatching) ───────────────

    async def _lookup_episode(self, episode_id: int):
        return await self._feed_sync.lookup_episode(episode_id)

    async def _claim_dispatched(self, session, task_id: int) -> bool:
        return await self._transcription._claim_dispatched(session, task_id)

    async def _clear_dispatched(self, task_id: int) -> None:
        await self._transcription._clear_dispatched(task_id)
