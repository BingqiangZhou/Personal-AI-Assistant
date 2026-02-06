"""Celery tasks for recommendation generation."""

from app.core.celery_app import celery_app
from app.domains.podcast import tasks_legacy


@celery_app.task
def generate_podcast_recommendations():
    return tasks_legacy.generate_podcast_recommendations.run()

