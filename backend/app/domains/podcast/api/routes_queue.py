"""Podcast queue routes."""

from fastapi import APIRouter, Depends, HTTPException, status

from app.domains.podcast.api.dependencies import get_queue_service
from app.domains.podcast.schemas import (
    PodcastQueueActivateRequest,
    PodcastQueueCurrentCompleteRequest,
    PodcastQueueItemAddRequest,
    PodcastQueueReorderRequest,
    PodcastQueueResponse,
    PodcastQueueSetCurrentRequest,
)
from app.domains.podcast.services.queue_service import PodcastQueueService


router = APIRouter(prefix="")


def _bilingual_error(
    message_en: str,
    message_zh: str,
    status_code: int,
) -> HTTPException:
    return HTTPException(
        status_code=status_code,
        detail={"message_en": message_en, "message_zh": message_zh},
    )


@router.get("/queue", response_model=PodcastQueueResponse, summary="Get playback queue")
async def get_queue(
    service: PodcastQueueService = Depends(get_queue_service),
):
    return await service.get_queue()


@router.post(
    "/queue/items",
    response_model=PodcastQueueResponse,
    summary="Add episode to queue",
)
async def add_queue_item(
    request: PodcastQueueItemAddRequest,
    service: PodcastQueueService = Depends(get_queue_service),
):
    try:
        return await service.add_to_queue(request.episode_id)
    except ValueError as exc:
        if str(exc) == "EPISODE_NOT_FOUND":
            raise _bilingual_error(
                "Episode not found",
                "\u672a\u627e\u5230\u8be5\u5355\u96c6",
                status.HTTP_404_NOT_FOUND,
            ) from exc
        if str(exc) == "QUEUE_LIMIT_EXCEEDED":
            raise _bilingual_error(
                "Queue has reached its limit",
                "\u64ad\u653e\u961f\u5217\u5df2\u8fbe\u5230\u4e0a\u9650",
                status.HTTP_400_BAD_REQUEST,
            ) from exc
        raise _bilingual_error(
            "Failed to add episode",
            "\u52a0\u5165\u961f\u5217\u5931\u8d25",
            status.HTTP_400_BAD_REQUEST,
        ) from exc


@router.delete(
    "/queue/items/{episode_id}",
    response_model=PodcastQueueResponse,
    summary="Remove episode from queue",
)
async def remove_queue_item(
    episode_id: int,
    service: PodcastQueueService = Depends(get_queue_service),
):
    return await service.remove_from_queue(episode_id)


@router.put(
    "/queue/items/reorder",
    response_model=PodcastQueueResponse,
    summary="Reorder queue",
)
async def reorder_queue_items(
    request: PodcastQueueReorderRequest,
    service: PodcastQueueService = Depends(get_queue_service),
):
    try:
        return await service.reorder_queue(request.episode_ids)
    except ValueError as exc:
        if str(exc) == "INVALID_REORDER_PAYLOAD":
            raise _bilingual_error(
                "Invalid reorder payload",
                "\u91cd\u6392\u53c2\u6570\u65e0\u6548",
                status.HTTP_400_BAD_REQUEST,
            ) from exc
        raise _bilingual_error(
            "Failed to reorder queue",
            "\u91cd\u6392\u961f\u5217\u5931\u8d25",
            status.HTTP_400_BAD_REQUEST,
        ) from exc


@router.post(
    "/queue/current",
    response_model=PodcastQueueResponse,
    summary="Set current queue episode",
)
async def set_queue_current(
    request: PodcastQueueSetCurrentRequest,
    service: PodcastQueueService = Depends(get_queue_service),
):
    try:
        return await service.set_current(request.episode_id)
    except ValueError as exc:
        if str(exc) == "EPISODE_NOT_IN_QUEUE":
            raise _bilingual_error(
                "Episode not in queue",
                "\u8be5\u5355\u96c6\u4e0d\u5728\u961f\u5217\u4e2d",
                status.HTTP_400_BAD_REQUEST,
            ) from exc
        raise _bilingual_error(
            "Failed to set current",
            "\u8bbe\u7f6e\u5f53\u524d\u64ad\u653e\u5931\u8d25",
            status.HTTP_400_BAD_REQUEST,
        ) from exc


@router.post(
    "/queue/activate",
    response_model=PodcastQueueResponse,
    summary="Activate queue episode (ensure in queue + move to head + set current)",
)
async def activate_queue_episode(
    request: PodcastQueueActivateRequest,
    service: PodcastQueueService = Depends(get_queue_service),
):
    try:
        return await service.activate_episode(request.episode_id)
    except ValueError as exc:
        if str(exc) == "EPISODE_NOT_FOUND":
            raise _bilingual_error(
                "Episode not found",
                "\u672a\u627e\u5230\u8be5\u5355\u96c6",
                status.HTTP_404_NOT_FOUND,
            ) from exc
        if str(exc) == "QUEUE_LIMIT_EXCEEDED":
            raise _bilingual_error(
                "Queue has reached its limit",
                "\u64ad\u653e\u961f\u5217\u5df2\u8fbe\u5230\u4e0a\u9650",
                status.HTTP_400_BAD_REQUEST,
            ) from exc
        raise _bilingual_error(
            "Failed to activate episode",
            "\u6fc0\u6d3b\u64ad\u653e\u961f\u5217\u5931\u8d25",
            status.HTTP_400_BAD_REQUEST,
        ) from exc


@router.post(
    "/queue/current/complete",
    response_model=PodcastQueueResponse,
    summary="Complete current queue episode and advance",
)
async def complete_queue_current(
    _request: PodcastQueueCurrentCompleteRequest,
    service: PodcastQueueService = Depends(get_queue_service),
):
    return await service.complete_current()
