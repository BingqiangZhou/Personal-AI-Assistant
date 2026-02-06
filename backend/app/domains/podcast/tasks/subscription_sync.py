"""Celery tasks for subscription sync flows."""

import asyncio
from datetime import datetime

from app.core.celery_app import celery_app
from app.domains.podcast import tasks_legacy
from app.domains.podcast.tasks._runlog import _insert_run_async


@celery_app.task(bind=True, max_retries=3)
def refresh_all_podcast_feeds(self):
    started_at = datetime.utcnow()
    task_name = "app.domains.podcast.tasks.subscription_sync.refresh_all_podcast_feeds"
    queue_name = "subscription_sync"
    try:
        result = tasks_legacy.refresh_all_podcast_feeds.run()
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

