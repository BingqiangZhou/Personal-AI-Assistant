import logging
from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.podcast.models import ProcessingStatus
from app.domains.podcast.schemas import (
    EpisodeListResponse,
    PodcastDetail,
    PodcastListResponse,
    PodcastTrackResponse,
    SyncResponse,
)
from app.domains.podcast.service import EpisodeService, PodcastService

router = APIRouter(tags=["podcasts"])
logger = logging.getLogger(__name__)


@router.get("/podcasts", response_model=PodcastListResponse)
async def list_podcasts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    category: str | None = Query(None),
    is_tracked: bool | None = Query(None),
    search: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
) -> PodcastListResponse:
    service = PodcastService(db)
    return await service.list_podcasts(
        page=page,
        page_size=page_size,
        category=category,
        is_tracked=is_tracked,
        search=search,
    )


@router.get("/podcasts/{podcast_id}", response_model=PodcastDetail)
async def get_podcast(
    podcast_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> PodcastDetail:
    service = PodcastService(db)
    podcast = await service.get_podcast(podcast_id)
    if podcast is None:
        raise HTTPException(status_code=404, detail="Podcast not found")
    return podcast


@router.post("/podcasts/{podcast_id}/track", response_model=PodcastTrackResponse)
async def toggle_track_podcast(
    podcast_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> PodcastTrackResponse:
    service = PodcastService(db)
    podcast = await service.get_podcast(podcast_id)
    if podcast is None:
        raise HTTPException(status_code=404, detail="Podcast not found")

    if podcast.is_tracked:
        result = await service.untrack_podcast(podcast_id)
    else:
        result = await service.track_podcast(podcast_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Podcast not found")
    return result


@router.post("/podcasts/sync", response_model=SyncResponse)
async def sync_podcasts(
    db: AsyncSession = Depends(get_db),
) -> SyncResponse:
    from app.core.celery_app import celery_app

    task = celery_app.send_task("app.domains.podcast.tasks.sync_rankings_task")
    logger.info(f"Triggered ranking sync task: {task.id}")
    return SyncResponse(
        message="Ranking sync triggered",
        task_id=task.id,
    )


@router.get("/podcasts/{podcast_id}/episodes", response_model=EpisodeListResponse)
async def get_podcast_episodes(
    podcast_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> EpisodeListResponse:
    service = EpisodeService(db)
    return await service.list_episodes(
        page=page,
        page_size=page_size,
        podcast_id=podcast_id,
    )
