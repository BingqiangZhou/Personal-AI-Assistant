"""Podcast stats routes."""

from fastapi import APIRouter, Depends, Request, Response

from app.core.etag import generate_etag, matches_any_etag
from app.core.etag_response import ETagResponse
from app.domains.podcast.api.dependencies import get_podcast_service
from app.domains.podcast.schemas import PodcastStatsResponse
from app.domains.podcast.services import PodcastService


router = APIRouter(prefix="")


@router.get(
    "/stats",
    response_model=PodcastStatsResponse,
    summary="获取播客统计信息",
)
async def get_podcast_stats(
    request: Request,
    service: PodcastService = Depends(get_podcast_service),
):
    """获取用户的播客收听统计。"""
    stats = await service.get_user_stats()
    response_data = PodcastStatsResponse(**stats)

    if_none_match = request.headers.get("if-none-match")
    if if_none_match:
        current_etag = generate_etag(response_data.dict(), weak=True)
        if matches_any_etag(current_etag, if_none_match):
            return Response(
                status_code=304,
                headers={"ETag": current_etag, "Cache-Control": "private, max-age=300"},
            )

    return ETagResponse(
        content=response_data.dict(),
        max_age=300,
        weak=True,
        cache_control="private, max-age=300",
    )
