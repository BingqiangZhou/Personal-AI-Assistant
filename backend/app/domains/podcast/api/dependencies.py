"""Podcast API dependencies.

Centralized providers for route-level dependency injection.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.security import get_token_from_request
from app.domains.podcast.conversation_service import ConversationService
from app.domains.podcast.services.daily_report_service import DailyReportService
from app.domains.podcast.services.episode_service import PodcastEpisodeService
from app.domains.podcast.services.playback_service import PodcastPlaybackService
from app.domains.podcast.services.queue_service import PodcastQueueService
from app.domains.podcast.services.schedule_service import PodcastScheduleService
from app.domains.podcast.services.search_service import PodcastSearchService
from app.domains.podcast.services.stats_service import PodcastStatsService
from app.domains.podcast.services.subscription_service import PodcastSubscriptionService
from app.domains.podcast.services.summary_service import PodcastSummaryService
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.podcast.transcription_scheduler import TranscriptionScheduler


async def get_current_user_id(user=Depends(get_token_from_request)) -> int:
    """Get current authenticated user id from token payload."""
    return int(user["sub"])


def get_subscription_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastSubscriptionService:
    """Provide subscription service for the current request."""
    return PodcastSubscriptionService(db, user_id)


def get_episode_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastEpisodeService:
    """Provide episode service for the current request."""
    return PodcastEpisodeService(db, user_id)


def get_playback_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastPlaybackService:
    """Provide playback service for the current request."""
    return PodcastPlaybackService(db, user_id)


def get_queue_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastQueueService:
    """Provide queue service for the current request."""
    return PodcastQueueService(db, user_id)


def get_schedule_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastScheduleService:
    """Provide schedule service for the current request."""
    return PodcastScheduleService(db, user_id)


def get_search_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastSearchService:
    """Provide search/recommendation service for the current request."""
    return PodcastSearchService(db, user_id)


def get_stats_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastStatsService:
    """Provide stats service for the current request."""
    return PodcastStatsService(db, user_id)


def get_daily_report_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> DailyReportService:
    """Provide daily report service for the current request."""
    return DailyReportService(db, user_id)


def get_summary_domain_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastSummaryService:
    """Provide summary domain service for the current request."""
    return PodcastSummaryService(db, user_id)


def get_transcription_service(
    db: AsyncSession = Depends(get_db_session),
) -> DatabaseBackedTranscriptionService:
    """Provide transcription service for the current request."""
    return DatabaseBackedTranscriptionService(db)


def get_summary_service(
    db: AsyncSession = Depends(get_db_session),
) -> DatabaseBackedAISummaryService:
    """Provide AI summary service for the current request."""
    return DatabaseBackedAISummaryService(db)


def get_scheduler(
    db: AsyncSession = Depends(get_db_session),
) -> TranscriptionScheduler:
    """Provide transcription scheduler for the current request."""
    return TranscriptionScheduler(db)


def get_conversation_service(
    db: AsyncSession = Depends(get_db_session),
) -> ConversationService:
    """Provide conversation service for the current request."""
    return ConversationService(db)
