from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "poddigest",
    broker=str(settings.CELERY_BROKER_URL),
    backend=str(settings.CELERY_RESULT_BACKEND),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "app.domains.podcast.tasks.sync_rankings_task": {"queue": "default"},
        "app.domains.podcast.tasks.sync_episodes_task": {"queue": "default"},
        "app.domains.transcription.tasks.transcribe_episode_task": {"queue": "transcription"},
        "app.domains.summary.tasks.summarize_episode_task": {"queue": "summary"},
    },
    beat_schedule={
        "sync-rankings-daily": {
            "task": "app.domains.podcast.tasks.sync_rankings_task",
            "schedule": 86400.0,  # 24 hours
        },
        "sync-episodes-every-6-hours": {
            "task": "app.domains.podcast.tasks.sync_episodes_task",
            "schedule": 21600.0,  # 6 hours
        },
    },
)

celery_app.autodiscover_tasks(
    [
        "app.domains.podcast",
        "app.domains.transcription",
        "app.domains.summary",
    ]
)
