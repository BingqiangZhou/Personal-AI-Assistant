"""Celery tasks for summary generation flows."""

from datetime import datetime

from app.core.celery_app import celery_app
from app.domains.podcast.tasks.handlers_summary import (
    generate_pending_summaries_handler,
    generate_summary_for_episode_handler,
)
from app.domains.podcast.tasks.runtime import log_task_run, run_async, worker_session


@celery_app.task(bind=True, max_retries=3)
def generate_pending_summaries(self):
    started_at = datetime.utcnow()
    task_name = "app.domains.podcast.tasks.summary_generation.generate_pending_summaries"
    queue_name = "ai_generation"
    try:
        result = run_async(_generate_pending_summaries())
        log_task_run(
            task_name=task_name,
            queue_name=queue_name,
            status="success",
            started_at=started_at,
            finished_at=datetime.utcnow(),
        )
        return result
    except Exception as exc:
        log_task_run(
            task_name=task_name,
            queue_name=queue_name,
            status="failed",
            started_at=started_at,
            finished_at=datetime.utcnow(),
            error_message=str(exc),
        )
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries)) from exc
        raise


async def _generate_pending_summaries():
    async with worker_session("celery-summary-worker") as session:
        return await generate_pending_summaries_handler(session)


@celery_app.task(bind=True, max_retries=3)
def generate_summary_for_episode(self, episode_id: int, user_id: int):
    started_at = datetime.utcnow()
    task_name = "app.domains.podcast.tasks.summary_generation.generate_summary_for_episode"
    queue_name = "ai_generation"
    try:
        result = run_async(_generate_episode_summary(episode_id=episode_id, user_id=user_id))
        log_task_run(
            task_name=task_name,
            queue_name=queue_name,
            status="success",
            started_at=started_at,
            finished_at=datetime.utcnow(),
            metadata={"episode_id": episode_id, "user_id": user_id},
        )
        return result
    except Exception as exc:
        log_task_run(
            task_name=task_name,
            queue_name=queue_name,
            status="failed",
            started_at=started_at,
            finished_at=datetime.utcnow(),
            error_message=str(exc),
            metadata={"episode_id": episode_id, "user_id": user_id},
        )
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries)) from exc
        raise


async def _generate_episode_summary(episode_id: int, user_id: int):
    async with worker_session("celery-single-summary-worker") as session:
        return await generate_summary_for_episode_handler(
            session=session,
            episode_id=episode_id,
            user_id=user_id,
        )
