import logging
from uuid import UUID

from app.core.celery_app import celery_app
from app.core.database import async_session_factory

logger = logging.getLogger(__name__)


@celery_app.task(
    name="app.domains.transcription.tasks.transcribe_episode_task",
    bind=True,
    max_retries=3,
    default_retry_delay=120,
)
def transcribe_episode_task(self, episode_id: str) -> dict:
    """Celery task: transcribe an episode.

    Args:
        episode_id: The episode UUID as string.

    Returns:
        Dict with transcription result status.
    """
    import asyncio
    from uuid import UUID

    from app.domains.transcription.service import TranscriptionService

    async def _run() -> dict:
        async with async_session_factory() as session:
            try:
                service = TranscriptionService(session)
                transcript = await service.transcribe_episode(UUID(episode_id))
                await session.commit()
                return {
                    "episode_id": episode_id,
                    "transcript_id": str(transcript.id),
                    "status": transcript.status.value,
                    "word_count": transcript.word_count,
                }
            except Exception:
                await session.rollback()
                raise

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Transcription task failed for episode {episode_id}: {exc}")
        raise self.retry(exc=exc, countdown=120)
