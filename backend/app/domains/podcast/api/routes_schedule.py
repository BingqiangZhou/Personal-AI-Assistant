"""Podcast schedule-related API routes."""

from fastapi import APIRouter, Body, Depends, HTTPException, status

from app.domains.podcast.api.dependencies import get_podcast_service
from app.domains.podcast.schemas import ScheduleConfigResponse, ScheduleConfigUpdate
from app.domains.podcast.services import PodcastService


router = APIRouter(prefix="")


@router.get(
    "/subscriptions/{subscription_id}/schedule",
    response_model=ScheduleConfigResponse,
    summary="Get subscription schedule configuration",
    description="Get the current schedule configuration for a subscription",
)
async def get_subscription_schedule(
    subscription_id: int,
    service: PodcastService = Depends(get_podcast_service),
):
    schedule = await service.get_subscription_schedule(subscription_id)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found",
        )
    return ScheduleConfigResponse(**schedule)


@router.patch(
    "/subscriptions/{subscription_id}/schedule",
    response_model=ScheduleConfigResponse,
    summary="Update subscription schedule configuration",
    description="Update the schedule configuration for a subscription",
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found",
        )
    return ScheduleConfigResponse(**schedule)


@router.get(
    "/subscriptions/schedule/all",
    response_model=list[ScheduleConfigResponse],
    summary="Get all subscription schedules",
    description="Get schedule configuration for all user subscriptions",
)
async def get_all_subscription_schedules(
    service: PodcastService = Depends(get_podcast_service),
):
    rows = await service.get_all_subscription_schedules()
    return [ScheduleConfigResponse(**row) for row in rows]


@router.post(
    "/subscriptions/schedule/batch-update",
    response_model=list[ScheduleConfigResponse],
    summary="Batch update subscription schedules",
    description="Update schedule configuration for multiple subscriptions",
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
