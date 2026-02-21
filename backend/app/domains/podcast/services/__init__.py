"""
Podcast domain services - Refactored into specialized services.

For backward compatibility, PodcastService facade is available from:
    from app.domains.podcast.services import PodcastService

Or use specialized services directly for better separation of concerns.
"""
# ruff: noqa: I001

from .episode_service import PodcastEpisodeService
from .daily_report_service import DailyReportService
from .playback_service import PodcastPlaybackService
from .queue_service import PodcastQueueService
from .schedule_service import PodcastScheduleService
from .search_service import PodcastSearchService
from .stats_service import PodcastStatsService
from .subscription_service import PodcastSubscriptionService
from .summary_service import PodcastSummaryService
from .sync_service import PodcastSyncService

from app.domains.podcast.podcast_service_facade import PodcastService


__all__ = [
    "PodcastService",
    "PodcastSubscriptionService",
    "PodcastEpisodeService",
    "DailyReportService",
    "PodcastPlaybackService",
    "PodcastQueueService",
    "PodcastSummaryService",
    "PodcastSearchService",
    "PodcastSyncService",
    "PodcastScheduleService",
    "PodcastStatsService",
]
