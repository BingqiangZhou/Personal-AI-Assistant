import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.podcast.models import ProcessingStatus
from app.domains.podcast.repository import EpisodeRepository
from app.domains.podcast.schemas import SyncResponse
from app.domains.transcription.schemas import TranscribeRequest, TranscriptDetail, TranscriptResponse
from app.domains.transcription.service import TranscriptionService

router = APIRouter(tags=["transcription"])
logger = logging.getLogger(__name__)


@router.post("/episodes/{episode_id}/transcribe", response_model=SyncResponse)
async def transcribe_episode(
    episode_id: UUID,
    request: TranscribeRequest | None = None,
    db: AsyncSession = Depends(get_db),
) -> SyncResponse:
    """Trigger transcription for an episode."""
    # Verify episode exists
    episode_repo = EpisodeRepository(db)
    episode = await episode_repo.get(episode_id)
    if episode is None:
        raise HTTPException(status_code=404, detail="Episode not found")

    if not episode.audio_url:
        raise HTTPException(status_code=400, detail="Episode has no audio URL")

    # Check if already processing or completed
    if episode.transcript_status == ProcessingStatus.PROCESSING:
        raise HTTPException(status_code=409, detail="Transcription already in progress")

    from app.core.celery_app import celery_app

    task_kwargs = {"episode_id": str(episode_id)}
    if request and request.language:
        task_kwargs["language"] = request.language
    if request and request.model:
        task_kwargs["model"] = request.model

    task = celery_app.send_task(
        "app.domains.transcription.tasks.transcribe_episode_task",
        args=[str(episode_id)],
    )
    logger.info(f"Triggered transcription task for episode {episode_id}: {task.id}")

    return SyncResponse(
        message="Transcription triggered",
        task_id=task.id,
    )


@router.get("/episodes/{episode_id}/transcript", response_model=TranscriptDetail)
async def get_transcript(
    episode_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> TranscriptDetail:
    """Get transcript for an episode."""
    service = TranscriptionService(db)
    transcript = await service.get_transcript(episode_id)
    if transcript is None:
        raise HTTPException(status_code=404, detail="Transcript not found")
    return TranscriptDetail.model_validate(transcript)


@router.post("/episodes/{episode_id}/transcribe/retry", response_model=SyncResponse)
async def retry_transcription(
    episode_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> SyncResponse:
    """Retry failed transcription for an episode."""
    episode_repo = EpisodeRepository(db)
    episode = await episode_repo.get(episode_id)
    if episode is None:
        raise HTTPException(status_code=404, detail="Episode not found")

    if episode.transcript_status != ProcessingStatus.FAILED:
        raise HTTPException(
            status_code=400,
            detail="Can only retry failed transcriptions",
        )

    from app.core.celery_app import celery_app

    task = celery_app.send_task(
        "app.domains.transcription.tasks.transcribe_episode_task",
        args=[str(episode_id)],
    )
    logger.info(f"Retrying transcription for episode {episode_id}: {task.id}")

    return SyncResponse(
        message="Transcription retry triggered",
        task_id=task.id,
    )
