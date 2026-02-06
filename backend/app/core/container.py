"""Lightweight dependency providers.

This module intentionally avoids an external DI framework. It keeps
provider functions compatible with existing import paths.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.podcast_service_facade import PodcastService
from app.domains.podcast.services import (
    PodcastEpisodeService,
    PodcastPlaybackService,
    PodcastSearchService,
    PodcastSubscriptionService,
    PodcastSummaryService,
)


def get_container() -> None:
    """Compatibility shim for removed DI container."""
    return None


def get_podcast_service(db: AsyncSession, user_id: int) -> PodcastService:
    """Get PodcastService for a request."""
    return PodcastService(db, user_id)


def get_podcast_subscription_service(db: AsyncSession, user_id: int) -> PodcastSubscriptionService:
    """Get PodcastSubscriptionService for a request."""
    return PodcastSubscriptionService(db, user_id)


def get_podcast_episode_service(db: AsyncSession, user_id: int) -> PodcastEpisodeService:
    """Get PodcastEpisodeService for a request."""
    return PodcastEpisodeService(db, user_id)


def get_podcast_playback_service(db: AsyncSession, user_id: int) -> PodcastPlaybackService:
    """Get PodcastPlaybackService for a request."""
    return PodcastPlaybackService(db, user_id)


def get_podcast_summary_service(db: AsyncSession, user_id: int) -> PodcastSummaryService:
    """Get PodcastSummaryService for a request."""
    return PodcastSummaryService(db, user_id)


def get_podcast_search_service(db: AsyncSession, user_id: int) -> PodcastSearchService:
    """Get PodcastSearchService for a request."""
    return PodcastSearchService(db, user_id)
