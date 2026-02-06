"""Podcast stats service.

Provides aggregated user-level podcast stats and cache handling.
"""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import PodcastRedis
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.services.playback_service import PodcastPlaybackService


logger = logging.getLogger(__name__)


class PodcastStatsService:
    """Service for user podcast statistics."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = PodcastRepository(db)
        self.playback_service = PodcastPlaybackService(db, user_id)
        self.redis = PodcastRedis()

    async def get_user_stats(self) -> dict[str, Any]:
        """Get cached/aggregated user stats with playback context."""
        cached = await self.redis.get_user_stats(self.user_id)
        if cached:
            logger.info("Cache HIT for user stats: user_id=%s", self.user_id)
            return cached

        logger.info("Cache MISS for user stats: user_id=%s", self.user_id)

        stats = await self.repo.get_user_stats_aggregated(self.user_id)
        recently_played = await self.playback_service.get_recently_played(limit=5)
        listening_streak = await self.playback_service.calculate_listening_streak()

        result = {
            **stats,
            "recently_played": recently_played,
            "top_categories": [],
            "listening_streak": listening_streak,
        }

        await self.redis.set_user_stats(self.user_id, result)
        return result
