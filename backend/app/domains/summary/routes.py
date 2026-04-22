import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.podcast.models import ProcessingStatus
from app.domains.podcast.repository import EpisodeRepository
from app.domains.podcast.schemas import SyncResponse
from app.domains.summary.schemas import SummaryDetail, SummaryResponse
from app.domains.summary.service import SummaryService

router = APIRouter(tags=["summary"])
logger = logging.getLogger(__name__)


@router.post("/episodes/{episode_id}/summarize", response_model=SyncResponse)
async def summarize_episode(
    episode_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> SyncResponse:
    """Trigger summarization for an episode."""
    # Verify episode exists
    episode_repo = EpisodeRepository(db)
    episode = await episode_repo.get(episode_id)
    if episode is None:
        raise HTTPException(status_code=404, detail="Episode not found")

    # Check transcript exists
    if episode.transcript_status != ProcessingStatus.COMPLETED:
        raise HTTPException(
            status_code=400,
            detail="Episode must have a completed transcript before summarization",
        )

    # Check if already processing
    if episode.summary_status == ProcessingStatus.PROCESSING:
        raise HTTPException(status_code=409, detail="Summarization already in progress")

    from app.core.celery_app import celery_app

    task = celery_app.send_task(
        "app.domains.summary.tasks.summarize_episode_task",
        args=[str(episode_id)],
    )
    logger.info(f"Triggered summarization task for episode {episode_id}: {task.id}")

    return SyncResponse(
        message="Summarization triggered",
        task_id=task.id,
    )


@router.get("/episodes/{episode_id}/summary", response_model=SummaryDetail)
async def get_summary(
    episode_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> SummaryDetail:
    """Get summary for an episode."""
    service = SummaryService(db)
    summary = await service.get_summary(episode_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Summary not found")
    return SummaryDetail.model_validate(summary)
