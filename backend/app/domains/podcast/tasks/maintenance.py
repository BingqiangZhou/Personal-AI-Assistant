"""Celery tasks for maintenance and housekeeping."""

from app.core.celery_app import celery_app
from app.domains.podcast import tasks_legacy


@celery_app.task
def cleanup_old_playback_states():
    return tasks_legacy.cleanup_old_playback_states.run()


@celery_app.task
def cleanup_old_transcription_temp_files(days: int = 7):
    return tasks_legacy.cleanup_old_transcription_temp_files.run(days)


@celery_app.task
def log_periodic_task_statistics():
    return tasks_legacy.log_periodic_task_statistics.run()


@celery_app.task
def auto_cleanup_cache_files():
    return tasks_legacy.auto_cleanup_cache_files.run()

