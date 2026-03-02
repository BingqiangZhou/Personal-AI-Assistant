"""
Podcast Sync Service - Handles background synchronization tasks.

播客同步服务 - 处理后台同步任务
"""

import logging

from sqlalchemy.ext.asyncio import AsyncSession


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

        # Import transcription service
        from app.domains.podcast.transcription_manager import (
            DatabaseBackedTranscriptionService,
        )
        self.transcription_service = DatabaseBackedTranscriptionService(db)

    async def trigger_transcription(self, episode_id: int) -> dict | None:
        """
        Trigger transcription task for an episode.

        Args:
            episode_id: Episode ID

        Returns:
            Task dict or None
        """
        try:
            # Create and schedule transcription task
            result = await self.transcription_service.start_transcription(episode_id)
            logger.info(
                "Created and scheduled transcription task %s for episode %s (action=%s)",
                result["task"].id,
                episode_id,
                result["action"],
            )
            return {"task_id": result["task"].id, "episode_id": episode_id}
        except Exception as e:
            logger.error(f"Failed to create transcription task for episode {episode_id}: {e}")
            return None
