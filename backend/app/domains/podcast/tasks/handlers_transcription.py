"""Handlers for transcription Celery tasks."""

from __future__ import annotations

from app.domains.podcast.services.task_orchestration_service import (
    PodcastTaskOrchestrationService,
)


async def process_audio_transcription_handler(
    session,
    task_id: int,
    config_db_id: int | None = None,
) -> dict:
    """Execute transcription with lock + redis state updates."""
    return await PodcastTaskOrchestrationService(session).process_audio_transcription_task(
        task_id=task_id,
        config_db_id=config_db_id,
    )


async def process_podcast_episode_with_transcription_handler(
    session,
    episode_id: int,
    user_id: int,
) -> dict:
    """Dispatch the transcription pipeline and return immediately."""
    return await PodcastTaskOrchestrationService(
        session
    ).trigger_episode_transcription_pipeline(
        episode_id=episode_id,
        user_id=user_id,
    )
