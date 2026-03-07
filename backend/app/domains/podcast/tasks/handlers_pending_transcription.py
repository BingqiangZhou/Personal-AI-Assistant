"""Handlers for periodic transcription backlog dispatch."""

from __future__ import annotations

from app.domains.podcast.services.task_orchestration_service import (
    PodcastTaskOrchestrationService,
)


async def process_pending_transcriptions_handler(session) -> dict:
    """Dispatch periodic backlog transcription tasks."""
    return await PodcastTaskOrchestrationService(session).process_pending_transcriptions()
