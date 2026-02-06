"""Celery configuration snapshot checks."""

from app.core.celery_app import celery_app


def test_celery_task_routes_snapshot() -> None:
    task_routes = celery_app.conf.task_routes

    assert "app.domains.podcast.tasks.subscription_sync.refresh_all_podcast_feeds" in task_routes
    assert "app.domains.podcast.tasks.summary_generation.generate_pending_summaries" in task_routes
    assert "app.domains.podcast.tasks.transcription.process_audio_transcription" in task_routes
    assert "app.domains.podcast.tasks.maintenance.cleanup_old_playback_states" in task_routes
    assert "app.domains.podcast.tasks.recommendation.generate_podcast_recommendations" in task_routes

    assert task_routes[
        "app.domains.podcast.tasks.subscription_sync.refresh_all_podcast_feeds"
    ]["queue"] == "subscription_sync"
    assert task_routes[
        "app.domains.podcast.tasks.transcription.process_audio_transcription"
    ]["queue"] == "transcription"


def test_celery_beat_schedule_snapshot() -> None:
    beat_schedule = celery_app.conf.beat_schedule

    assert "refresh-podcast-feeds" in beat_schedule
    assert "generate-pending-summaries" in beat_schedule
    assert "log-task-statistics" in beat_schedule
    assert "auto-cleanup-cache" in beat_schedule

