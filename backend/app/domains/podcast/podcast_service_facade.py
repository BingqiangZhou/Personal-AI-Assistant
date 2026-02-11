"""Podcast facade service.

Backward-compatible facade that delegates to specialized services.
"""

# ruff: noqa: UP007
import warnings
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.models import PodcastEpisode
from app.domains.podcast.services.episode_service import PodcastEpisodeService
from app.domains.podcast.services.playback_service import PodcastPlaybackService
from app.domains.podcast.services.queue_service import PodcastQueueService
from app.domains.podcast.services.schedule_service import PodcastScheduleService
from app.domains.podcast.services.search_service import PodcastSearchService
from app.domains.podcast.services.stats_service import PodcastStatsService
from app.domains.podcast.services.subscription_service import PodcastSubscriptionService
from app.domains.podcast.services.summary_service import PodcastSummaryService
from app.domains.podcast.services.sync_service import PodcastSyncService
from app.domains.subscription.models import Subscription


class PodcastService:
    """Backward-compatible facade for podcast domain services."""

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id

        self.subscription_service = PodcastSubscriptionService(db, user_id)
        self.episode_service = PodcastEpisodeService(db, user_id)
        self.playback_service = PodcastPlaybackService(db, user_id)
        self.queue_service = PodcastQueueService(db, user_id)
        self.summary_service = PodcastSummaryService(db, user_id)
        self.search_service = PodcastSearchService(db, user_id)
        self.sync_service = PodcastSyncService(db, user_id)
        self.schedule_service = PodcastScheduleService(db, user_id)
        self.stats_service = PodcastStatsService(db, user_id)

        # Direct repo access kept for compatibility methods.
        from app.domains.podcast.repositories import PodcastRepository

        self.repo = PodcastRepository(db)

    def _warn_deprecated_private(self, method_name: str) -> None:
        warnings.warn(
            (
                f"PodcastService.{method_name} is deprecated and kept only for "
                "backward compatibility. Use specialized services directly."
            ),
            DeprecationWarning,
            stacklevel=2,
        )

    # Subscription management
    async def add_subscription(
        self,
        feed_url: str,
    ) -> tuple[Subscription, list[PodcastEpisode]]:
        return await self.subscription_service.add_subscription(feed_url)

    async def add_subscriptions_batch(
        self, subscriptions_data: list
    ) -> list[dict[str, Any]]:
        return await self.subscription_service.add_subscriptions_batch(
            subscriptions_data
        )

    async def list_subscriptions(
        self,
        filters: dict | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict], int]:
        return await self.subscription_service.list_subscriptions(filters, page, size)

    async def get_subscription_details(self, subscription_id: int) -> dict | None:
        return await self.subscription_service.get_subscription_details(subscription_id)

    async def refresh_subscription(self, subscription_id: int) -> list[PodcastEpisode]:
        return await self.subscription_service.refresh_subscription(subscription_id)

    async def reparse_subscription(
        self, subscription_id: int, force_all: bool = False
    ) -> dict:
        return await self.subscription_service.reparse_subscription(
            subscription_id, force_all
        )

    async def remove_subscription(self, subscription_id: int) -> bool:
        return await self.subscription_service.remove_subscription(subscription_id)

    async def remove_subscriptions_bulk(
        self, subscription_ids: list[int]
    ) -> dict[str, Any]:
        return await self.subscription_service.remove_subscriptions_bulk(
            subscription_ids
        )

    # Episode management
    async def list_episodes(
        self,
        filters: dict | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict], int]:
        return await self.episode_service.list_episodes(filters, page, size)

    async def get_playback_history(
        self,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict], int]:
        return await self.episode_service.list_playback_history(page=page, size=size)

    async def get_episode_by_id(
        self,
        episode_id: int,
        user_id: int | None = None,
    ) -> PodcastEpisode | None:
        return await self.repo.get_episode_by_id(episode_id, user_id)

    async def get_episode_with_summary(self, episode_id: int) -> dict | None:
        return await self.episode_service.get_episode_with_summary(episode_id)

    async def get_subscription_by_id(self, subscription_id: int) -> Subscription | None:
        return await self.repo.get_subscription_by_id(self.user_id, subscription_id)

    # Schedule management
    async def get_subscription_schedule(
        self, subscription_id: int
    ) -> dict[str, Any] | None:
        return await self.schedule_service.get_subscription_schedule(subscription_id)

    async def update_subscription_schedule(
        self,
        subscription_id: int,
        update_frequency: str | None,
        update_time: str | None,
        update_day_of_week: int | None,
        fetch_interval: int | None,
    ) -> dict[str, Any] | None:
        return await self.schedule_service.update_subscription_schedule(
            subscription_id=subscription_id,
            update_frequency=update_frequency,
            update_time=update_time,
            update_day_of_week=update_day_of_week,
            fetch_interval=fetch_interval,
        )

    async def get_all_subscription_schedules(self) -> list[dict[str, Any]]:
        return await self.schedule_service.get_all_subscription_schedules()

    async def batch_update_subscription_schedules(
        self,
        subscription_ids: list[int],
        update_frequency: str | None,
        update_time: str | None,
        update_day_of_week: int | None,
        fetch_interval: int | None,
    ) -> list[dict[str, Any]]:
        return await self.schedule_service.batch_update_subscription_schedules(
            subscription_ids=subscription_ids,
            update_frequency=update_frequency,
            update_time=update_time,
            update_day_of_week=update_day_of_week,
            fetch_interval=fetch_interval,
        )

    # Playback management
    async def update_playback_progress(
        self,
        episode_id: int,
        progress_seconds: int,
        is_playing: bool = False,
        playback_rate: float = 1.0,
    ) -> dict:
        return await self.playback_service.update_playback_progress(
            episode_id,
            progress_seconds,
            is_playing,
            playback_rate,
        )

    async def get_playback_state(self, episode_id: int) -> dict | None:
        return await self.playback_service.get_playback_state(episode_id)

    async def get_effective_playback_rate(
        self,
        subscription_id: int | None = None,
    ) -> dict[str, Any]:
        return await self.playback_service.get_effective_playback_rate(subscription_id)

    async def apply_playback_rate_preference(
        self,
        playback_rate: float,
        apply_to_subscription: bool,
        subscription_id: int | None = None,
    ) -> dict[str, Any]:
        return await self.playback_service.apply_playback_rate_preference(
            playback_rate=playback_rate,
            apply_to_subscription=apply_to_subscription,
            subscription_id=subscription_id,
        )

    # Queue management
    async def get_queue(self) -> dict[str, Any]:
        return await self.queue_service.get_queue()

    async def add_queue_item(self, episode_id: int) -> dict[str, Any]:
        return await self.queue_service.add_to_queue(episode_id)

    async def remove_queue_item(self, episode_id: int) -> dict[str, Any]:
        return await self.queue_service.remove_from_queue(episode_id)

    async def reorder_queue_items(self, episode_ids: list[int]) -> dict[str, Any]:
        return await self.queue_service.reorder_queue(episode_ids)

    async def set_queue_current(self, episode_id: int) -> dict[str, Any]:
        return await self.queue_service.set_current(episode_id)

    async def complete_queue_current(self) -> dict[str, Any]:
        return await self.queue_service.complete_current()

    # Summary management
    async def generate_summary_for_episode(self, episode_id: int) -> str:
        return await self.summary_service.generate_summary_for_episode(episode_id)

    async def regenerate_summary(self, episode_id: int, force: bool = False) -> str:
        return await self.summary_service.regenerate_summary(episode_id, force)

    async def get_pending_summaries(self) -> list[dict]:
        return await self.summary_service.get_pending_summaries()

    # Search and recommendations
    async def search_podcasts(
        self,
        query: str,
        search_in: str = "all",
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict], int]:
        return await self.search_service.search_podcasts(query, search_in, page, size)

    async def get_recommendations(self, limit: int = 10) -> list[dict]:
        return await self.search_service.get_recommendations(limit)

    # Stats
    async def get_user_stats(self) -> dict[str, Any]:
        return await self.stats_service.get_user_stats()

    # Deprecated private compatibility methods (still used by tasks/tests)
    async def _generate_summary_task(self, episode: PodcastEpisode):
        self._warn_deprecated_private("_generate_summary_task")
        await self.summary_service._generate_summary_task(episode)

    async def _generate_summary(
        self, episode: PodcastEpisode, version: str = "v1"
    ) -> str:
        self._warn_deprecated_private("_generate_summary")
        return await self.summary_service._generate_summary(episode, version)

    async def _call_llm_for_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str,
    ) -> str:
        self._warn_deprecated_private("_call_llm_for_summary")
        return await self.summary_service._call_llm_for_summary(
            episode_title,
            content,
            content_type,
        )

    def _rule_based_summary(self, title: str, content: str) -> str:
        self._warn_deprecated_private("_rule_based_summary")

        import re

        sentences = re.split(r"[.!?]", content)
        important_sentences = [
            sentence.strip()[:200]
            for sentence in sentences
            if any(
                keyword in sentence.lower()
                for keyword in [
                    "key",
                    "main",
                    "conclusion",
                    "important",
                    "learn",
                    "feel",
                ]
            )
        ][:3]

        if important_sentences:
            bullet_points = "\n".join(
                f"- {sentence}" for sentence in important_sentences
            )
        else:
            bullet_points = f"- {content[:150]}..."

        disclaimer = "*Quick fallback summary without model inference.*"
        return (
            "## Podcast Summary\n\n"
            f"**Episode**: {title}\n\n"
            f"{bullet_points}\n\n"
            f"{disclaimer}"
        )

    async def _calculate_listening_streak(self) -> int:
        self._warn_deprecated_private("_calculate_listening_streak")
        return await self.playback_service.calculate_listening_streak()
