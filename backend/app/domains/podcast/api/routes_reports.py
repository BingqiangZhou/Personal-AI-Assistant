"""Podcast daily report routes."""

from datetime import date

from fastapi import APIRouter, Depends, Query

from app.domains.podcast.api.dependencies import get_podcast_service
from app.domains.podcast.schemas import (
    PodcastDailyReportDatesResponse,
    PodcastDailyReportResponse,
)
from app.domains.podcast.services import PodcastService


router = APIRouter(prefix="")


@router.get(
    "/reports/daily",
    response_model=PodcastDailyReportResponse,
    summary="Get daily podcast report",
)
async def get_daily_report(
    report_date: date | None = Query(None, alias="date", description="YYYY-MM-DD"),
    service: PodcastService = Depends(get_podcast_service),
):
    payload = await service.get_daily_report(target_date=report_date)
    return PodcastDailyReportResponse(**payload)


@router.post(
    "/reports/daily/generate",
    response_model=PodcastDailyReportResponse,
    summary="Generate daily podcast report",
)
async def generate_daily_report(
    report_date: date | None = Query(None, alias="date", description="YYYY-MM-DD"),
    service: PodcastService = Depends(get_podcast_service),
):
    payload = await service.generate_daily_report(target_date=report_date)
    return PodcastDailyReportResponse(**payload)


@router.get(
    "/reports/daily/dates",
    response_model=PodcastDailyReportDatesResponse,
    summary="List available daily report dates",
)
async def list_daily_report_dates(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(30, ge=1, le=100, description="Page size"),
    service: PodcastService = Depends(get_podcast_service),
):
    payload = await service.list_daily_report_dates(page=page, size=size)
    return PodcastDailyReportDatesResponse(**payload)
