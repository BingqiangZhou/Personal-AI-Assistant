"""Podcast episode, summary, search, and recommendation routes."""
# ruff: noqa

import base64
import binascii
import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.config import settings
from app.core.etag import build_conditional_etag_response
from app.domains.podcast.api.dependencies import (
    get_episode_service,
    get_playback_service,
    get_search_service,
    get_summary_domain_service,
    get_summary_service,
)
from app.domains.podcast.schemas import (
    PlaybackRateApplyRequest,
    PlaybackRateEffectiveResponse,
    PodcastEpisodeDetailResponse,
    PodcastEpisodeFilter,
    PodcastPlaybackHistoryItemResponse,
    PodcastPlaybackHistoryListResponse,
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
from app.domains.podcast.services.episode_service import PodcastEpisodeService
from app.domains.podcast.services.playback_service import PodcastPlaybackService
from app.domains.podcast.services.search_service import PodcastSearchService
from app.domains.podcast.services.summary_service import PodcastSummaryService
from app.domains.podcast.summary_manager import DatabaseBackedAISummaryService


router = APIRouter(prefix="")
logger = logging.getLogger(__name__)


def _bilingual_error(
    message_en: str,
    message_zh: str,
    status_code: int,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"message_en": message_en, "message_zh": message_zh},
    )


def _encode_keyset_cursor(
    cursor_type: str, timestamp: datetime, episode_id: int
) -> str:
    # Normalize to naive UTC to avoid tz-aware/naive comparison issues in SQL filters.
    normalized = timestamp
    if normalized.tzinfo is not None:
        normalized = normalized.astimezone(timezone.utc).replace(tzinfo=None)

    payload = {
        "v": 2,
        "type": cursor_type,
        "ts": normalized.isoformat(),
        "id": episode_id,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _decode_cursor(cursor: str) -> dict[str, Any]:
    """Decode keyset cursor token."""
    padding = "=" * (-len(cursor) % 4)
    try:
        decoded = base64.urlsafe_b64decode(f"{cursor}{padding}").decode("utf-8")
    except (ValueError, binascii.Error) as exc:
        raise _bilingual_error(
            "Invalid cursor",
            "游标参数无效",
            status.HTTP_400_BAD_REQUEST,
        ) from exc

    try:
        payload = json.loads(decoded)
        if not isinstance(payload, dict):
            raise ValueError("payload must be object")

        cursor_type = payload.get("type")
        timestamp_raw = payload.get("ts")
        episode_id = payload.get("id")
        if cursor_type not in {"feed", "history"}:
            raise ValueError("unsupported cursor type")
        if not isinstance(timestamp_raw, str):
            raise ValueError("timestamp missing")
        if not isinstance(episode_id, int) or episode_id <= 0:
            raise ValueError("episode id missing")

        timestamp = datetime.fromisoformat(timestamp_raw)
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

        return {
            "type": cursor_type,
            "ts": timestamp,
            "id": episode_id,
        }
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise _bilingual_error(
            "Invalid cursor",
            "游标参数无效",
            status.HTTP_400_BAD_REQUEST,
        ) from exc


@router.get(
    "/episodes/feed",
    response_model=PodcastFeedResponse,
    summary="Get podcast feed",
)
async def get_podcast_feed(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    cursor: str | None = Query(None, description="Cursor token for pagination"),
    page_size: int = Query(10, ge=1, le=50, description="Page size"),
    size: int | None = Query(
        None,
        ge=1,
        le=50,
        description="Optional alias for page_size",
    ),
    service: PodcastEpisodeService = Depends(get_episode_service),
):
    """Return all subscribed episodes ordered by publish date desc."""
    resolved_size = size or page_size
    decoded_cursor = _decode_cursor(cursor) if cursor else None

    should_use_first_page_keyset = (
        settings.PODCAST_FEED_LIGHTWEIGHT_ENABLED and cursor is None and page == 1
    )
    if should_use_first_page_keyset:
        (
            episodes,
            total,
            has_more,
            next_cursor_values,
        ) = await service.list_feed_by_cursor(size=resolved_size)
        next_page = None
        next_cursor = (
            _encode_keyset_cursor("feed", next_cursor_values[0], next_cursor_values[1])
            if next_cursor_values
            else None
        )
    elif decoded_cursor:
        if decoded_cursor["type"] != "feed":
            raise _bilingual_error(
                "Cursor is not valid for this endpoint",
                "该游标不适用于当前接口",
                status.HTTP_400_BAD_REQUEST,
            )

        (
            episodes,
            total,
            has_more,
            next_cursor_values,
        ) = await service.list_feed_by_cursor(
            size=resolved_size,
            cursor_published_at=decoded_cursor["ts"],
            cursor_episode_id=decoded_cursor["id"],
        )
        next_page = None
        next_cursor = (
            _encode_keyset_cursor("feed", next_cursor_values[0], next_cursor_values[1])
            if next_cursor_values
            else None
        )
    else:
        episodes, total = await service.list_feed_by_page(
            page=page,
            size=resolved_size,
        )
        has_more = (page * resolved_size) < total
        next_page = page + 1 if has_more else None
        next_cursor = None

    episode_responses = [PodcastEpisodeResponse(**ep) for ep in episodes]

    response_data = PodcastFeedResponse(
        items=episode_responses,
        has_more=has_more,
        next_page=next_page,
        next_cursor=next_cursor,
        total=total,
    )
    return build_conditional_etag_response(
        request=request,
        content=response_data,
        max_age=30 if settings.PODCAST_FEED_LIGHTWEIGHT_ENABLED else 600,
        cache_control=(
            "private, max-age=30"
            if settings.PODCAST_FEED_LIGHTWEIGHT_ENABLED
            else "private, max-age=600"
        ),
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
    service: PodcastEpisodeService = Depends(get_episode_service),
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
    "/episodes/history",
    response_model=PodcastEpisodeListResponse,
    summary="List playback history",
)
async def list_playback_history(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    cursor: str | None = Query(None, description="Cursor token for pagination"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    service: PodcastEpisodeService = Depends(get_episode_service),
):
    decoded_cursor = _decode_cursor(cursor) if cursor else None

    if decoded_cursor:
        if decoded_cursor["type"] != "history":
            raise _bilingual_error(
                "Cursor is not valid for this endpoint",
                "该游标不适用于当前接口",
                status.HTTP_400_BAD_REQUEST,
            )

        (
            episodes,
            total,
            _,
            next_cursor_values,
        ) = await service.list_playback_history_by_cursor(
            size=size,
            cursor_last_updated_at=decoded_cursor["ts"],
            cursor_episode_id=decoded_cursor["id"],
        )
        resolved_page = page
        next_cursor = (
            _encode_keyset_cursor(
                "history", next_cursor_values[0], next_cursor_values[1]
            )
            if next_cursor_values
            else None
        )
    else:
        episodes, total = await service.list_playback_history(
            page=page, size=size
        )
        resolved_page = page
        next_cursor = None

    episode_responses = [PodcastEpisodeResponse(**ep) for ep in episodes]
    pages = (total + size - 1) // size

    response_data = PodcastEpisodeListResponse(
        episodes=episode_responses,
        total=total,
        page=resolved_page,
        size=size,
        pages=pages,
        subscription_id=0,
        next_cursor=next_cursor,
    )
    return build_conditional_etag_response(
        request=request,
        content=response_data,
        max_age=300,
        cache_control="private, max-age=300",
    )


@router.get(
    "/episodes/history-lite",
    response_model=PodcastPlaybackHistoryListResponse,
    summary="List lightweight playback history",
)
async def list_playback_history_lite(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    service: PodcastEpisodeService = Depends(get_episode_service),
):
    episodes, total = await service.list_playback_history_lite(page=page, size=size)
    episode_responses = [PodcastPlaybackHistoryItemResponse(**ep) for ep in episodes]
    pages = (total + size - 1) // size

    return PodcastPlaybackHistoryListResponse(
        episodes=episode_responses,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get(
    "/episodes/{episode_id}",
    response_model=PodcastEpisodeDetailResponse,
    summary="Get episode detail",
)
async def get_episode(
    request: Request,
    episode_id: int,
    service: PodcastEpisodeService = Depends(get_episode_service),
):
    episode = await service.get_episode_with_summary(episode_id)
    if not episode:
        raise HTTPException(
            status_code=404, detail="Episode not found or no permission"
        )

    response_data = PodcastEpisodeDetailResponse(**episode)
    return build_conditional_etag_response(
        request=request,
        content=response_data,
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
    service: PodcastEpisodeService = Depends(get_episode_service),
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

        # Read back the final persisted value to keep POST response aligned with
        # episode detail API payload.
        episode_detail = await service.get_episode_with_summary(episode_id)
        final_summary = ""
        final_version = "1.0"
        if episode_detail:
            final_summary = episode_detail.get("ai_summary") or ""
            final_version = episode_detail.get("summary_version") or "1.0"

        return PodcastSummaryResponse(
            episode_id=episode_id,
            summary=final_summary,
            version=final_version,
            confidence_score=None,
            transcript_used=True,
            generated_at=datetime.now(timezone.utc),
            word_count=len(final_summary.split()),
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
    service: PodcastPlaybackService = Depends(get_playback_service),
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
            playback_rate=result["playback_rate"],
            play_count=result["play_count"],
            last_updated_at=result["last_updated_at"],
            progress_percentage=result["progress_percentage"],
            remaining_time=result["remaining_time"],
        )
    except ValueError as exc:
        if str(exc) == "Episode not found":
            raise _bilingual_error(
                "Episode not found",
                "未找到该单集",
                status.HTTP_404_NOT_FOUND,
            ) from exc
        raise _bilingual_error(
            "Failed to update playback progress",
            "更新播放进度失败",
            status.HTTP_400_BAD_REQUEST,
        ) from exc
    except Exception as exc:
        raise _bilingual_error(
            "Failed to update playback progress",
            "更新播放进度失败",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from exc


@router.get(
    "/episodes/{episode_id}/playback",
    response_model=PodcastPlaybackStateResponse,
    summary="Get playback state",
)
async def get_playback_state(
    episode_id: int,
    service: PodcastPlaybackService = Depends(get_playback_service),
):
    try:
        playback = await service.get_playback_state(episode_id)
        if not playback:
            raise HTTPException(status_code=404, detail="Playback record not found")

        return PodcastPlaybackStateResponse(**playback)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get(
    "/playback/rate/effective",
    response_model=PlaybackRateEffectiveResponse,
    summary="Get effective playback rate preference",
)
async def get_effective_playback_rate(
    subscription_id: Optional[int] = Query(
        None,
        ge=1,
        description="Subscription ID (optional)",
    ),
    service: PodcastPlaybackService = Depends(get_playback_service),
):
    result = await service.get_effective_playback_rate(subscription_id=subscription_id)
    return PlaybackRateEffectiveResponse(**result)


@router.put(
    "/playback/rate/apply",
    response_model=PlaybackRateEffectiveResponse,
    summary="Apply playback rate preference",
)
async def apply_playback_rate_preference(
    request: PlaybackRateApplyRequest,
    service: PodcastPlaybackService = Depends(get_playback_service),
):
    try:
        result = await service.apply_playback_rate_preference(
            playback_rate=request.playback_rate,
            apply_to_subscription=request.apply_to_subscription,
            subscription_id=request.subscription_id,
        )
        return PlaybackRateEffectiveResponse(**result)
    except ValueError as exc:
        code = str(exc)
        if code == "SUBSCRIPTION_ID_REQUIRED":
            raise _bilingual_error(
                "subscription_id is required when apply_to_subscription is true",
                "subscription_id is required",
                status.HTTP_400_BAD_REQUEST,
            ) from exc
        if code == "SUBSCRIPTION_NOT_FOUND":
            raise _bilingual_error(
                "Subscription not found",
                "未找到该订阅",
                status.HTTP_404_NOT_FOUND,
            ) from exc
        if code == "USER_NOT_FOUND":
            raise _bilingual_error(
                "User not found",
                "User not found",
                status.HTTP_404_NOT_FOUND,
            ) from exc
        raise _bilingual_error(
            "Failed to apply playback preference",
            "应用播放偏好失败",
            status.HTTP_400_BAD_REQUEST,
        ) from exc
    except Exception as exc:
        logger.error("Failed to apply playback rate preference: %s", exc)
        raise _bilingual_error(
            "Failed to apply playback preference",
            "应用播放偏好失败",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
        ) from exc


@router.get(
    "/summaries/pending",
    response_model=PodcastSummaryPendingResponse,
    summary="List pending summaries",
)
async def get_pending_summaries(
    service: PodcastSummaryService = Depends(get_summary_domain_service),
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
    q: Optional[str] = Query(None, min_length=1, description="Search keyword"),
    search_in: Optional[str] = Query(
        "all", description="Search scope: title, description, summary, all"
    ),
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    service: PodcastSearchService = Depends(get_search_service),
):
    keyword = (q or "").strip()
    if not keyword:
        raise _bilingual_error(
            "q is required",
            "必须提供 q 参数",
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        )

    episodes, total = await service.search_podcasts(
        query=keyword,
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
    service: PodcastSearchService = Depends(get_search_service),
):
    return await service.get_recommendations(limit=limit)
