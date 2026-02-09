"""
Podcast Episode Service - Manages podcast episodes.

播客单集服务 - 管理播客单集
"""

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import PodcastRedis
from app.core.utils import filter_thinking_content
from app.domains.podcast.models import PodcastEpisode
from app.domains.podcast.repositories import PodcastRepository


logger = logging.getLogger(__name__)


class PodcastEpisodeService:
    """
    Service for managing podcast episodes.

    Handles:
    - Listing episodes with pagination
    - Getting episode details
    - Episode metadata management
    """

    def __init__(self, db: AsyncSession, user_id: int):
        """
        Initialize episode service.

        Args:
            db: Database session
            user_id: Current user ID
        """
        self.db = db
        self.user_id = user_id
        self.repo = PodcastRepository(db)
        self.redis = PodcastRedis()

    async def list_episodes(
        self,
        filters: Any | None = None,
        page: int = 1,
        size: int = 20
    ) -> tuple[list[dict], int]:
        """
        List podcast episodes with pagination.

        Args:
            filters: Optional PodcastEpisodeFilter Pydantic model (subscription_id, has_summary, is_played)
            page: Page number
            size: Items per page

        Returns:
            Tuple of (episodes list, total count)
        """
        # Handle both dict and Pydantic model inputs
        if filters is None:
            subscription_id = None
        elif isinstance(filters, dict):
            subscription_id = filters.get('subscription_id')
        else:
            # Pydantic model - access attributes directly
            subscription_id = getattr(filters, 'subscription_id', None)

        # Try cache first
        if subscription_id:
            cached = await self.redis.get_episode_list(subscription_id, page, size)
            if cached:
                logger.info(f"Cache HIT for episode list: sub_id={subscription_id}, page={page}")
                return cached['results'], cached['total']

            logger.info(f"Cache MISS for episode list: sub_id={subscription_id}, page={page}")

        episodes, total = await self.repo.get_episodes_paginated(
            self.user_id,
            page=page,
            size=size,
            filters=filters
        )

        # Batch fetch playback states
        episode_ids = [ep.id for ep in episodes]
        playback_states = await self.repo.get_playback_states_batch(self.user_id, episode_ids)

        # Build response
        results = self._build_episode_response(episodes, playback_states)

        # Cache if filtering by subscription
        if subscription_id:
            await self.redis.set_episode_list(subscription_id, page, size, {
                'results': results,
                'total': total
            })

        return results, total

    async def get_episode_by_id(self, episode_id: int) -> PodcastEpisode | None:
        """
        Get episode by ID.

        Args:
            episode_id: Episode ID

        Returns:
            PodcastEpisode or None
        """
        return await self.repo.get_episode_by_id(episode_id, self.user_id)

    async def get_episode_with_summary(self, episode_id: int) -> dict | None:
        """
        Get episode details with AI summary.

        Args:
            episode_id: Episode ID

        Returns:
            Episode details dict or None
        """
        # Import here to avoid circular dependency
        from app.domains.podcast.services.summary_service import PodcastSummaryService

        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            return None

        # Trigger background summary if pending
        if not episode.ai_summary and episode.status == "pending_summary":
            summary_service = PodcastSummaryService(self.db, self.user_id)
            import asyncio
            asyncio.create_task(summary_service._generate_summary_task(episode))

        playback = await self.repo.get_playback_state(self.user_id, episode_id)
        cleaned_summary = filter_thinking_content(episode.ai_summary)

        # Extract subscription metadata
        subscription_image_url = None
        subscription_author = None
        subscription_categories = []
        if episode.subscription and episode.subscription.config:
            config = episode.subscription.config
            subscription_image_url = config.get("image_url")
            subscription_author = config.get("author")
            subscription_categories = config.get("categories") or []

        return {
            "id": episode.id,
            "subscription_id": episode.subscription_id,
            "title": episode.title,
            "description": episode.description,
            "audio_url": episode.audio_url,
            "audio_duration": episode.audio_duration,
            "audio_file_size": episode.audio_file_size,
            "published_at": episode.published_at,
            "image_url": episode.image_url,
            "item_link": episode.item_link,
            "subscription_image_url": subscription_image_url,
            "transcript_url": episode.transcript_url,
            "transcript_content": episode.transcript_content,
            "ai_summary": cleaned_summary,
            "summary_version": episode.summary_version,
            "ai_confidence_score": episode.ai_confidence_score,
            "play_count": episode.play_count,
            "last_played_at": episode.last_played_at,
            "season": episode.season,
            "episode_number": episode.episode_number,
            "explicit": episode.explicit,
            "status": episode.status,
            "metadata": episode.metadata_json or {},
            "created_at": episode.created_at,
            "updated_at": episode.updated_at,
            "playback_position": playback.current_position if playback else None,
            "is_playing": playback.is_playing if playback else False,
            "playback_rate": playback.playback_rate if playback else 1.0,
            "is_played": None,
            "subscription": {
                "id": episode.subscription.id,
                "title": episode.subscription.title,
                "description": episode.subscription.description,
                "image_url": subscription_image_url,
                "author": subscription_author,
                "categories": subscription_categories
            } if episode.subscription else None,
            "related_episodes": []
        }

    async def get_recently_played(
        self,
        user_id: int,
        limit: int = 5
    ) -> list[dict[str, Any]]:
        """
        Get recently played episodes.

        Args:
            user_id: User ID
            limit: Maximum number of episodes

        Returns:
            List of recently played episodes
        """
        return await self.repo.get_recently_played(user_id, limit)

    async def get_liked_episodes(
        self,
        user_id: int,
        limit: int = 20
    ) -> list[PodcastEpisode]:
        """
        Get user's liked episodes (high completion rate).

        Args:
            user_id: User ID
            limit: Maximum number of episodes

        Returns:
            List of liked episodes
        """
        return await self.repo.get_liked_episodes(user_id, limit)

    def _build_episode_response(
        self,
        episodes: list[PodcastEpisode],
        playback_states: dict[int, Any]
    ) -> list[dict]:
        """
        Build episode response list with playback states.

        Args:
            episodes: List of podcast episodes
            playback_states: Dictionary mapping episode_id to playback state

        Returns:
            List of episode response dictionaries
        """
        results = []
        for ep in episodes:
            playback = playback_states.get(ep.id)
            cleaned_summary = filter_thinking_content(ep.ai_summary)

            # Extract image URL from subscription config
            subscription_image_url = None
            if ep.subscription and ep.subscription.config:
                subscription_image_url = ep.subscription.config.get("image_url")

            # Use episode image_url or fallback to subscription image
            image_url = ep.image_url or subscription_image_url

            # Calculate is_played
            is_played = bool(
                playback and playback.current_position and
                ep.audio_duration and
                playback.current_position >= ep.audio_duration * 0.9
            )

            results.append({
                "id": ep.id,
                "subscription_id": ep.subscription_id,
                "subscription_title": ep.subscription.title if ep.subscription else None,
                "subscription_image_url": subscription_image_url,
                "title": ep.title,
                "description": ep.description,
                "audio_url": ep.audio_url,
                "audio_duration": ep.audio_duration,
                "audio_file_size": ep.audio_file_size,
                "published_at": ep.published_at,
                "image_url": image_url,
                "item_link": ep.item_link,
                "transcript_url": ep.transcript_url,
                "transcript_content": ep.transcript_content,
                "ai_summary": cleaned_summary,
                "summary_version": ep.summary_version,
                "ai_confidence_score": ep.ai_confidence_score,
                "play_count": ep.play_count,
                "last_played_at": ep.last_played_at,
                "season": ep.season,
                "episode_number": ep.episode_number,
                "explicit": ep.explicit,
                "status": ep.status,
                "metadata": ep.metadata_json,
                "playback_position": playback.current_position if playback else None,
                "is_playing": playback.is_playing if playback else False,
                "playback_rate": playback.playback_rate if playback else 1.0,
                "is_played": is_played,
                "created_at": ep.created_at,
                "updated_at": ep.updated_at,
            })

        return results
