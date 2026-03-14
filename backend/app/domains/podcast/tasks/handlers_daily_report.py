"""Handlers for daily report background tasks."""

from __future__ import annotations

from datetime import date

from app.domains.podcast.services.task_orchestration_service import (
    PodcastTaskOrchestrationService,
)


async def generate_daily_reports_handler(
    session,
    target_date: date | None = None,
) -> dict:
    """Generate one daily report snapshot for each user with active subscriptions."""
    return await PodcastTaskOrchestrationService(session).generate_daily_reports(
        target_date=target_date,
    )
