"""Handlers for recommendation generation tasks."""

from __future__ import annotations

from app.domains.podcast.services.task_orchestration_service import (
    PodcastTaskOrchestrationService,
)


async def generate_podcast_recommendations_handler(session) -> dict:
    """Generate recommendations for all active users."""
    return await PodcastTaskOrchestrationService(
        session,
    ).generate_podcast_recommendations()
