"""Celery schedule snapshot tests — single queue mode."""

from app.core.celery_app import celery_app


def test_all_beat_tasks_use_default_queue():
    """All beat schedule entries should target the default queue."""
    beat_schedule = celery_app.conf.beat_schedule
    assert beat_schedule

    for name, entry in beat_schedule.items():
        assert entry["options"]["queue"] == "default", (
            f"{name} should use default queue in single-user mode"
        )
