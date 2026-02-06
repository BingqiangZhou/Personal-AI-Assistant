"""Celery tasks for transcription flows."""

import asyncio
from datetime import datetime

from app.core.celery_app import celery_app
from app.domains.podcast import tasks_legacy
from app.domains.podcast.tasks._runlog import _insert_run_async


@celery_app.task(bind=True, max_retries=3)
def process_audio_transcription(self, task_id: int, config_db_id: int | None = None):
    started_at = datetime.utcnow()
    task_name = "app.domains.podcast.tasks.transcription.process_audio_transcription"
    queue_name = "transcription"
    try:
        result = tasks_legacy.process_audio_transcription.run(task_id, config_db_id)
        asyncio.run(
            _insert_run_async(
                task_name=task_name,
                queue_name=queue_name,
                status="success",
                started_at=started_at,
                finished_at=datetime.utcnow(),
                metadata={"task_id": task_id, "config_db_id": config_db_id},
            )
        )
        return result
    except Exception as exc:
        asyncio.run(
            _insert_run_async(
                task_name=task_name,
                queue_name=queue_name,
                status="failed",
                started_at=started_at,
                finished_at=datetime.utcnow(),
                error_message=str(exc),
                metadata={"task_id": task_id, "config_db_id": config_db_id},
            )
        )
        raise


@celery_app.task(bind=True, max_retries=3)
def process_podcast_episode_with_transcription(self, episode_id: int, user_id: int):
    return tasks_legacy.process_podcast_episode_with_transcription.run(episode_id, user_id)

