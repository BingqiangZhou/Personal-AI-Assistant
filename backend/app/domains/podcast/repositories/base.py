"""Shared repository base for podcast persistence helpers."""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import PodcastRedis, get_shared_redis
from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState
from app.domains.subscription.models import Subscription, UserSubscription


class BasePodcastRepository:
    """Small shared base for specialized podcast repositories."""

    def __init__(self, db: AsyncSession, redis: PodcastRedis | None = None):
        self.db = db
        self.redis = redis or get_shared_redis()
        self._queue_position_step = 1024
        self._queue_position_compaction_threshold = 1_000_000

    @staticmethod
    def _active_user_subscription_filters(user_id: int) -> tuple[Any, Any]:
        """Common filter for active user-subscription mappings."""
        return (
            UserSubscription.user_id == user_id,
            UserSubscription.is_archived.is_(False),
        )

    @staticmethod
    def _podcast_source_type_filter() -> Any:
        return Subscription.source_type.in_(["podcast-rss", "rss"])

    async def _resolve_window_total(
        self,
        rows: list[Any],
        *,
        total_index: int,
        fallback_count_query: Any,
    ) -> int:
        """Resolve paged total via window count with empty-page fallback."""
        if rows:
            return int(rows[0][total_index] or 0)
        return int(await self.db.scalar(fallback_count_query) or 0)

    async def get_playback_state(
        self, user_id: int, episode_id: int,
    ) -> PodcastPlaybackState | None:
        """Get playback state for one user and episode."""
        stmt = select(PodcastPlaybackState).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.episode_id == episode_id,
            ),
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def get_playback_states_batch(
        self, user_id: int, episode_ids: list[int],
    ) -> dict[int, PodcastPlaybackState]:
        """Batch fetch playback states for multiple episodes."""
        if not episode_ids:
            return {}

        stmt = select(PodcastPlaybackState).where(
            and_(
                PodcastPlaybackState.user_id == user_id,
                PodcastPlaybackState.episode_id.in_(episode_ids),
            ),
        )
        result = await self.db.execute(stmt)
        states = result.scalars().all()
        return {state.episode_id: state for state in states}

    async def _cache_episode_metadata(self, episode: PodcastEpisode):
        """Cache lightweight episode metadata when Redis is available."""
        if not self.redis:
            return

        metadata = {
            "id": str(episode.id),
            "title": episode.title,
            "audio_url": episode.audio_url,
            "duration": str(episode.audio_duration or 0),
            "has_summary": "yes" if episode.ai_summary else "no",
        }

        await self.redis.set_episode_metadata(episode.id, metadata)
