"""Podcast API dependencies.

Centralized providers for route-level dependency injection.
"""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.security import get_token_from_request
from app.domains.podcast.conversation_service import ConversationService
from app.domains.podcast.services import PodcastService
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.podcast.transcription_scheduler import TranscriptionScheduler


async def get_current_user_id(user=Depends(get_token_from_request)) -> int:
    """Get current authenticated user id from token payload."""
    return int(user["sub"])


def get_podcast_service(
    db: AsyncSession = Depends(get_db_session),
    user_id: int = Depends(get_current_user_id),
) -> PodcastService:
    """Provide PodcastService bound to current user and request DB session."""
    return PodcastService(db, user_id)


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
