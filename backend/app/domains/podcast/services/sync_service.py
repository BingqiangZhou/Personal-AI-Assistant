"""
Podcast Sync Service - Handles background synchronization tasks.

播客同步服务 - 处理后台同步任务
"""

import logging
import asyncio
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.models import PodcastEpisode

logger = logging.getLogger(__name__)


class PodcastSyncService:
    """
    Service for managing background synchronization tasks.

    Handles:
    - Triggering transcription tasks
    - Managing Celery background jobs
    """

    def __init__(self, db: AsyncSession, user_id: int):
        """
        Initialize sync service.

        Args:
            db: Database session
            user_id: Current user ID
        """
        self.db = db
        self.user_id = user_id
        self.repo = PodcastRepository(db)

        # Import transcription service
        from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
        self.transcription_service = DatabaseBackedTranscriptionService(db)

    async def trigger_transcription(self, episode_id: int) -> Optional[dict]:
        """
        Trigger transcription task for an episode.

        Args:
            episode_id: Episode ID

        Returns:
            Task dict or None
        """
        try:
            # Create and schedule transcription task
            task = await self.transcription_service.start_transcription(episode_id)
            logger.info(f"Created and scheduled transcription task {task.id} for episode {episode_id}")
            return {"task_id": task.id, "episode_id": episode_id}
        except Exception as e:
            logger.error(f"Failed to create transcription task for episode {episode_id}: {e}")
            return None

    async def process_new_episode(self, episode_id: int):
        """
        Process a new episode: trigger transcription and summary.

        This runs as a background task after adding new episodes.

        Args:
            episode_id: Episode ID
        """
        # Import here to avoid circular dependency
        from app.domains.podcast.services.summary_service import PodcastSummaryService

        try:
            # Trigger transcription
            await self.trigger_transcription(episode_id)

            # Trigger AI summary asynchronously
            episode = await self.repo.get_episode_by_id(episode_id)
            if episode:
                summary_service = PodcastSummaryService(self.db, self.user_id)
                asyncio.create_task(summary_service._generate_summary_task(episode))

        except Exception as e:
            logger.error(f"Failed to process new episode {episode_id}: {e}")
