"""
Podcast domain services - Refactored into specialized services.

播客域服务 - 重构为专业化服务

For backward compatibility, PodcastService facade is available from:
    from app.domains.podcast.services import PodcastService

Or use specialized services directly for better separation of concerns.
"""

# Import backward-compatible facade
from app.domains.podcast.podcast_service_facade import PodcastService

from .episode_service import PodcastEpisodeService
from .playback_service import PodcastPlaybackService
from .search_service import PodcastSearchService
from .subscription_service import PodcastSubscriptionService
from .summary_service import PodcastSummaryService
from .sync_service import PodcastSyncService


__all__ = [
    "PodcastService",  # Backward-compatible facade
    "PodcastSubscriptionService",
    "PodcastEpisodeService",
    "PodcastPlaybackService",
    "PodcastSummaryService",
    "PodcastSearchService",
    "PodcastSyncService",
]
