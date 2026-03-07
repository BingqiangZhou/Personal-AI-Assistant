"""Handlers for subscription sync background tasks."""

from __future__ import annotations

from app.domains.podcast.services.task_orchestration_service import (
    PodcastTaskOrchestrationService,
)


async def refresh_all_podcast_feeds_handler(session) -> dict:
    """Refresh all active podcast-rss subscriptions due by user schedule."""
    return await PodcastTaskOrchestrationService(session).refresh_all_podcast_feeds()
