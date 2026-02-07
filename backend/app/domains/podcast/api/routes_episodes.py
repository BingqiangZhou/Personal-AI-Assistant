"""Podcast episode, summary, search, and recommendation routes."""
# ruff: noqa

import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.etag import ETagResponse, check_etag_precondition
from app.domains.podcast.api.dependencies import (
    get_podcast_service,
    get_summary_service,
)
from app.domains.podcast.schemas import (
    PodcastEpisodeDetailResponse,
    PodcastEpisodeFilter,
    PodcastEpisodeListResponse,
    PodcastEpisodeResponse,
    PodcastFeedResponse,
    PodcastPlaybackStateResponse,
    PodcastPlaybackUpdate,
    PodcastSummaryPendingResponse,
    PodcastSummaryRequest,
    PodcastSummaryResponse,
    SummaryModelInfo,
    SummaryModelsResponse,
)
from app.domains.podcast.services import PodcastService
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService


router = APIRouter(prefix="")
logger = logging.getLogger(__name__)


@router.get(
    "/episodes/feed",
    response_model=PodcastFeedResponse,
    summary="Get podcast feed",
)
async def get_podcast_feed(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(10, ge=1, le=50, description="Page size"),
    service: PodcastService = Depends(get_podcast_service),
):
    """Return all subscribed episodes ordered by publish date desc."""
    episodes, total = await service.list_episodes(filters=None, page=page, size=page_size)
    episode_responses = [PodcastEpisodeResponse(**ep) for ep in episodes]

    has_more = (page * page_size) < total
    next_page = page + 1 if has_more else None

    response_data = PodcastFeedResponse(
        items=episode_responses,
        has_more=has_more,
        next_page=next_page,
        total=total,
    )

    etag_response = await check_etag_precondition(
        request,
        response_data.dict(),
        max_age=600,
        cache_control="private, max-age=600",
    )
    if etag_response:
        return etag_response

    return ETagResponse(
        content=response_data.dict(),
        max_age=600,
        cache_control="private, max-age=600",
    )


@router.get(
    "/episodes",
    response_model=PodcastEpisodeListResponse,
    summary="List podcast episodes",
)
async def list_episodes(
    subscription_id: Optional[int] = Query(None, description="Subscription ID filter"),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    has_summary: Optional[bool] = Query(None, description="Has AI summary"),
    is_played: Optional[bool] = Query(None, description="Played status"),
    service: PodcastService = Depends(get_podcast_service),
):
    filters = PodcastEpisodeFilter(
        subscription_id=subscription_id,
        has_summary=has_summary,
        is_played=is_played,
    )

    episodes, total = await service.list_episodes(filters=filters, page=page, size=size)
    episode_responses = [PodcastEpisodeResponse(**ep) for ep in episodes]

    pages = (total + size - 1) // size
    return PodcastEpisodeListResponse(
        episodes=episode_responses,
        total=total,
        page=page,
        size=size,
        pages=pages,
        subscription_id=subscription_id or 0,
    )


@router.get(
    "/episodes/{episode_id}",
    response_model=PodcastEpisodeDetailResponse,
    summary="Get episode detail",
)
async def get_episode(
    request: Request,
    episode_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    episode = await service.get_episode_with_summary(episode_id)
    if not episode:
        raise HTTPException(status_code=404, detail="Episode not found or no permission")

    response_data = PodcastEpisodeDetailResponse(**episode)

    etag_response = await check_etag_precondition(
        request,
        response_data.dict(),
        max_age=1800,
        cache_control="private, max-age=1800",
    )
    if etag_response:
        return etag_response

    return ETagResponse(
        content=response_data.dict(),
        max_age=1800,
        cache_control="private, max-age=1800",
    )


@router.post(
    "/episodes/{episode_id}/summary",
    response_model=PodcastSummaryResponse,
    summary="Generate or regenerate AI summary",
)
async def generate_summary(
    episode_id: int,
    request: PodcastSummaryRequest,
    service: PodcastService = Depends(get_podcast_service),
    ai_summary_service: DatabaseBackedAISummaryService = Depends(get_summary_service),
):
    try:
        episode = await service.get_episode_by_id(episode_id)
        if not episode:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Episode {episode_id} not found",
            )

        summary_result = await ai_summary_service.generate_summary(
            episode_id,
            request.summary_model,
            request.custom_prompt,
        )

        return PodcastSummaryResponse(
            episode_id=episode_id,
            summary=summary_result["summary_content"],
            version="1.0",
            confidence_score=None,
            transcript_used=True,
            generated_at=datetime.now(timezone.utc),
            word_count=len(summary_result["summary_content"].split()),
            model_used=summary_result["model_name"],
            processing_time=summary_result["processing_time"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to generate summary for episode %s: %s", episode_id, exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.put(
    "/episodes/{episode_id}/playback",
    response_model=PodcastPlaybackStateResponse,
    summary="Update playback progress",
)
async def update_playback_progress(
    episode_id: int,
    playback_data: PodcastPlaybackUpdate,
    service: PodcastService = Depends(get_podcast_service),
):
    try:
        result = await service.update_playback_progress(
            episode_id,
            playback_data.position,
            playback_data.is_playing,
            playback_data.playback_rate,
        )

        return PodcastPlaybackStateResponse(
            episode_id=episode_id,
            current_position=result["progress"],
            is_playing=result["is_playing"],
            playback_rate=result.get("playback_rate", 1.0),
            play_count=result.get("play_count", 0),
            last_updated_at=result.get("last_updated_at", datetime.now(timezone.utc)),
            progress_percentage=result.get("progress_percentage", 0),
            remaining_time=result.get("remaining_time", 0),
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/episodes/{episode_id}/playback",
    response_model=PodcastPlaybackStateResponse,
    summary="Get playback state",
)
async def get_playback_state(
    episode_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    try:
        playback = await service.get_playback_state(episode_id)
        if not playback:
            raise HTTPException(status_code=404, detail="Playback record not found")

        return PodcastPlaybackStateResponse(**playback)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/summaries/pending",
    response_model=PodcastSummaryPendingResponse,
    summary="List pending summaries",
)
async def get_pending_summaries(
    service: PodcastService = Depends(get_podcast_service),
):
    pending = await service.get_pending_summaries()
    return PodcastSummaryPendingResponse(count=len(pending), episodes=pending)


@router.get(
    "/summaries/models",
    response_model=SummaryModelsResponse,
    summary="List available summary models",
)
async def get_summary_models(
    ai_summary_service: DatabaseBackedAISummaryService = Depends(get_summary_service),
):
    try:
        models = await ai_summary_service.get_summary_models()

        model_infos = [
            SummaryModelInfo(
                id=model["id"],
                name=model["name"],
                display_name=model["display_name"],
                provider=model["provider"],
                model_id=model["model_id"],
                is_default=model["is_default"],
            )
            for model in models
        ]

        return SummaryModelsResponse(models=model_infos, total=len(model_infos))
    except Exception as exc:
        logger.error("Failed to get summary models: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/search",
    response_model=PodcastEpisodeListResponse,
    summary="Search podcast content",
)
async def search_podcasts(
    q: str = Query(..., min_length=1, description="Search keyword"),
    search_in: Optional[str] = Query(
        "all", description="Search scope: title, description, summary, all"
    ),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    service: PodcastService = Depends(get_podcast_service),
):
    episodes, total = await service.search_podcasts(
        query=q,
        search_in=search_in,
        page=page,
        size=size,
    )

    episode_responses = [PodcastEpisodeResponse(**ep) for ep in episodes]
    pages = (total + size - 1) // size

    return PodcastEpisodeListResponse(
        episodes=episode_responses,
        total=total,
        page=page,
        size=size,
        pages=pages,
        subscription_id=0,
    )


@router.get(
    "/recommendations",
    response_model=list[dict],
    summary="Get podcast recommendations",
)
async def get_recommendations(
    limit: int = Query(10, ge=1, le=50, description="Recommendation count"),
    service: PodcastService = Depends(get_podcast_service),
):
    return await service.get_recommendations(limit=limit)
