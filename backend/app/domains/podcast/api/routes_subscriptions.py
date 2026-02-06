"""Podcast subscription routes."""
# ruff: noqa

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.core.etag_response import ETagResponse, check_etag_precondition
from app.domains.podcast.api.dependencies import get_podcast_service
from app.domains.podcast.schemas import (
    PodcastSearchFilter,
    PodcastSubscriptionBatchResponse,
    PodcastSubscriptionBulkDelete,
    PodcastSubscriptionBulkDeleteResponse,
    PodcastSubscriptionCreate,
    PodcastSubscriptionListResponse,
    PodcastSubscriptionResponse,
)
from app.domains.podcast.services import PodcastService


router = APIRouter(prefix="")


@router.post(
    "/subscriptions",
    status_code=status.HTTP_201_CREATED,
    response_model=PodcastSubscriptionResponse,
    summary="Add podcast subscription",
    description="Add one subscription from RSS url",
)
async def add_subscription(
    subscription_data: PodcastSubscriptionCreate,
    service: PodcastService = Depends(get_podcast_service),
):
    try:
        subscription, new_episodes = await service.add_subscription(
            feed_url=subscription_data.feed_url,
            category_ids=subscription_data.category_ids,
        )

        response_data = {
            "id": subscription.id,
            "title": subscription.title,
            "description": subscription.description,
            "source_url": subscription.source_url,
            "status": subscription.status,
            "last_fetched_at": subscription.last_fetched_at,
            "error_message": subscription.error_message,
            "fetch_interval": subscription.fetch_interval,
            "episode_count": len(new_episodes),
            "unplayed_count": len(new_episodes),
            "created_at": subscription.created_at,
            "updated_at": subscription.updated_at,
        }
        return PodcastSubscriptionResponse(**response_data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to add subscription: {exc}")


@router.post(
    "/subscriptions/bulk",
    response_model=PodcastSubscriptionBatchResponse,
    summary="Bulk add subscriptions",
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
    "/subscriptions",
    response_model=PodcastSubscriptionListResponse,
    summary="List subscriptions",
)
async def list_subscriptions(
    request: Request,
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Page size"),
    category_id: Optional[int] = Query(None, description="Category filter"),
    status: Optional[str] = Query(None, description="Status filter"),
    service: PodcastService = Depends(get_podcast_service),
):
    filters = PodcastSearchFilter(category_id=category_id, status=status)
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

    etag_response = await check_etag_precondition(
        request,
        response_data.dict(),
        max_age=900,
        cache_control="private, max-age=900",
    )
    if etag_response:
        return etag_response

    return ETagResponse(
        content=response_data.dict(),
        max_age=900,
        cache_control="private, max-age=900",
    )


@router.post(
    "/subscriptions/bulk-delete",
    response_model=PodcastSubscriptionBulkDeleteResponse,
    summary="Bulk delete subscriptions",
    description="Delete subscriptions and related entities in batch",
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
    "/subscriptions/{subscription_id}",
    response_model=PodcastSubscriptionResponse,
    summary="Get subscription detail",
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


@router.delete(
    "/subscriptions/{subscription_id}",
    summary="Delete subscription",
)
async def delete_subscription(
    subscription_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    success = await service.remove_subscription(subscription_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return {"success": True, "message": "Subscription deleted"}
