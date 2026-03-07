"""Specialized podcast repository exports."""

from app.domains.podcast.repositories.base import BasePodcastRepository
from app.domains.podcast.repositories.specialized import (
    PodcastEpisodeRepository,
    PodcastPlaybackRepository,
    PodcastQueueRepository,
    PodcastSearchRepository,
    PodcastStatsRepository,
    PodcastSubscriptionRepository,
    PodcastSummaryRepository,
)


class PodcastRepository(PodcastEpisodeRepository):
    """Compatibility alias for legacy tests and transitional imports."""


__all__ = [
    "BasePodcastRepository",
    "PodcastEpisodeRepository",
    "PodcastPlaybackRepository",
    "PodcastQueueRepository",
    "PodcastRepository",
    "PodcastSearchRepository",
    "PodcastStatsRepository",
    "PodcastSubscriptionRepository",
    "PodcastSummaryRepository",
]
