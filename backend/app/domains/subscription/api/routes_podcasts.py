"""Podcast subscription routes under the subscription domain.

All endpoints here are mounted under:
    /api/v1/subscriptions/podcasts*
"""


from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status

from app.core.etag import build_conditional_etag_response
from app.domains.podcast.api.dependencies import get_podcast_service
from app.domains.podcast.schemas import (
    PodcastSearchFilter,
    PodcastSubscriptionBatchResponse,
    PodcastSubscriptionBulkDelete,
    PodcastSubscriptionBulkDeleteResponse,
    PodcastSubscriptionCreate,
    PodcastSubscriptionListResponse,
    PodcastSubscriptionResponse,
    ScheduleConfigResponse,
    ScheduleConfigUpdate,
)
from app.domains.podcast.services import PodcastService


router = APIRouter(prefix="/podcasts")


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=PodcastSubscriptionResponse,
    summary="Add podcast subscription",
)
async def add_subscription(
    subscription_data: PodcastSubscriptionCreate,
    service: PodcastService = Depends(get_podcast_service),
):
    try:
        subscription, new_episodes = await service.add_subscription(
            feed_url=subscription_data.feed_url
        )

        # Extract metadata from config
        config = subscription.config or {}
        image_url = config.get("image_url")
        # Fallback to subscription.image_url column if config doesn't have it
        if not image_url:
            image_url = subscription.image_url
        author = config.get("author")
        categories = config.get("categories") or []

        response_data = {
            "id": subscription.id,
            "user_id": service.user_id,
            "title": subscription.title,
            "description": subscription.description,
            "source_url": subscription.source_url,
            "status": subscription.status,
            "last_fetched_at": subscription.last_fetched_at,
            "error_message": subscription.error_message,
            "fetch_interval": subscription.fetch_interval,
            "episode_count": len(new_episodes),
            "unplayed_count": len(new_episodes),
            "image_url": image_url,
            "author": author,
            "categories": categories,
            "created_at": subscription.created_at,
            "updated_at": subscription.updated_at,
        }
        return PodcastSubscriptionResponse(**response_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to add subscription: {exc}")


@router.post(
    "/bulk",
    response_model=PodcastSubscriptionBatchResponse,
    summary="Bulk add podcast subscriptions",
)
async def create_subscriptions_batch(
    subscriptions_data: list[PodcastSubscriptionCreate],
    service: PodcastService = Depends(get_podcast_service),
):
    results = await service.add_subscriptions_batch(subscriptions_data)

    success_count = sum(1 for item in results if item["status"] == "success")
    skipped_count = sum(1 for item in results if item["status"] == "skipped")
    error_count = sum(1 for item in results if item["status"] == "error")

    return PodcastSubscriptionBatchResponse(
        results=results,
        total_requested=len(subscriptions_data),
        success_count=success_count,
        skipped_count=skipped_count,
        error_count=error_count,
    )


@router.get(
    "",
    response_model=PodcastSubscriptionListResponse,
    summary="List podcast subscriptions",
)
async def list_subscriptions(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    category_id: int | None = Query(None, description="Category filter"),
    status_filter: str | None = Query(None, alias="status", description="Status filter"),
    service: PodcastService = Depends(get_podcast_service),
):
    filters = PodcastSearchFilter(category_id=category_id, status=status_filter)
    subscriptions, total = await service.list_subscriptions(
        filters=filters,
        page=page,
        size=size,
    )

    subscription_responses = [PodcastSubscriptionResponse(**item) for item in subscriptions]
    pages = (total + size - 1) // size
    response_data = PodcastSubscriptionListResponse(
        subscriptions=subscription_responses,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )
    return build_conditional_etag_response(
        request=request,
        content=response_data,
        max_age=900,
        cache_control="private, max-age=900",
    )


@router.post(
    "/bulk-delete",
    response_model=PodcastSubscriptionBulkDeleteResponse,
    summary="Bulk delete podcast subscriptions",
)
async def delete_subscriptions_bulk(
    request: PodcastSubscriptionBulkDelete,
    service: PodcastService = Depends(get_podcast_service),
):
    result = await service.remove_subscriptions_bulk(request.subscription_ids)
    return PodcastSubscriptionBulkDeleteResponse(
        success_count=result["success_count"],
        failed_count=result["failed_count"],
        errors=result["errors"],
        deleted_subscription_ids=result["deleted_subscription_ids"],
    )


@router.get(
    "/{subscription_id}",
    response_model=PodcastSubscriptionResponse,
    summary="Get podcast subscription detail",
)
async def get_subscription(
    request: Request,
    subscription_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    details = await service.get_subscription_details(subscription_id)
    if not details:
        raise HTTPException(status_code=404, detail="Subscription not found or no permission")

    response_data = PodcastSubscriptionResponse(**details)
    return build_conditional_etag_response(
        request=request,
        content=response_data,
        max_age=1800,
        cache_control="private, max-age=1800",
    )


@router.delete(
    "/{subscription_id}",
    summary="Delete podcast subscription",
)
async def delete_subscription(
    subscription_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    success = await service.remove_subscription(subscription_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return {"success": True, "message": "Subscription deleted"}


@router.post(
    "/{subscription_id}/refresh",
    summary="Refresh podcast subscription",
)
async def refresh_subscription(
    subscription_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    try:
        new_episodes = await service.refresh_subscription(subscription_id)
        return {
            "success": True,
            "new_episodes": len(new_episodes),
            "message": f"Updated, found {len(new_episodes)} new episodes",
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/{subscription_id}/reparse",
    summary="Reparse podcast subscription",
)
async def reparse_subscription(
    subscription_id: int,
    force_all: bool = False,
    service: PodcastService = Depends(get_podcast_service),
):
    try:
        result = await service.reparse_subscription(subscription_id, force_all=force_all)
        return {"success": True, "result": result}
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/{subscription_id}/schedule",
    response_model=ScheduleConfigResponse,
    summary="Get podcast subscription schedule",
)
async def get_subscription_schedule(
    subscription_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    schedule = await service.get_subscription_schedule(subscription_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    return ScheduleConfigResponse(**schedule)


@router.patch(
    "/{subscription_id}/schedule",
    response_model=ScheduleConfigResponse,
    summary="Update podcast subscription schedule",
)
async def update_subscription_schedule(
    subscription_id: int,
    schedule_data: ScheduleConfigUpdate,
    service: PodcastService = Depends(get_podcast_service),
):
    schedule = await service.update_subscription_schedule(
        subscription_id=subscription_id,
        update_frequency=schedule_data.update_frequency,
        update_time=schedule_data.update_time,
        update_day_of_week=schedule_data.update_day_of_week,
        fetch_interval=schedule_data.fetch_interval,
    )
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Subscription not found")
    return ScheduleConfigResponse(**schedule)


@router.get(
    "/schedule/all",
    response_model=list[ScheduleConfigResponse],
    summary="Get all podcast subscription schedules",
)
async def get_all_subscription_schedules(
    service: PodcastService = Depends(get_podcast_service),
):
    rows = await service.get_all_subscription_schedules()
    return [ScheduleConfigResponse(**row) for row in rows]


@router.post(
    "/schedule/batch-update",
    response_model=list[ScheduleConfigResponse],
    summary="Batch update podcast subscription schedules",
)
async def batch_update_subscription_schedules(
    subscription_ids: list[int] = Body(..., embed=True),
    schedule_data: ScheduleConfigUpdate = Body(...),
    service: PodcastService = Depends(get_podcast_service),
):
    rows = await service.batch_update_subscription_schedules(
        subscription_ids=subscription_ids,
        update_frequency=schedule_data.update_frequency,
        update_time=schedule_data.update_time,
        update_day_of_week=schedule_data.update_day_of_week,
        fetch_interval=schedule_data.fetch_interval,
    )
    return [ScheduleConfigResponse(**row) for row in rows]
