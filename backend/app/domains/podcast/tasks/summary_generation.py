"""Celery tasks for summary generation flows."""

import asyncio
from datetime import datetime

from app.core.celery_app import celery_app
from app.domains.podcast import tasks_legacy
from app.domains.podcast.tasks._runlog import _insert_run_async


@celery_app.task(bind=True, max_retries=3)
def generate_pending_summaries(self):
    started_at = datetime.utcnow()
    task_name = "app.domains.podcast.tasks.summary_generation.generate_pending_summaries"
    queue_name = "ai_generation"
    try:
        result = tasks_legacy.generate_pending_summaries.run()
        asyncio.run(
            _insert_run_async(
                task_name=task_name,
                queue_name=queue_name,
                status="success",
                started_at=started_at,
                finished_at=datetime.utcnow(),
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
            )
        )
        raise


@celery_app.task
def generate_summary_for_episode(episode_id: int, user_id: int):
    return tasks_legacy.generate_summary_for_episode.run(episode_id, user_id)

