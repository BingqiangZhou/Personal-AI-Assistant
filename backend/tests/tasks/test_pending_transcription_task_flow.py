"""Pending-transcription backlog task flow tests."""

import pytest

from app.core.config import settings
from app.domains.podcast.tasks import pending_transcription
from app.domains.podcast.tasks.handlers_pending_transcription import (
    process_pending_transcriptions_handler,
)


@pytest.mark.asyncio
async def test_backlog_handler_dispatches_candidates(monkeypatch):
    async def _fetch(_session, _batch_size: int):
        return 37, [101, 102, 103]

    class _FakeService:
        def __init__(self, _session):
            pass

        async def start_transcription(self, _episode_id, force=False):
            assert force is False
            return {"action": "created"}

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription._fetch_pending_episode_ids",
        _fetch,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription.DatabaseBackedTranscriptionService",
        _FakeService,
    )

    result = await process_pending_transcriptions_handler(session=object())
    assert result["status"] == "success"
    assert result["total_candidates"] == 37
    assert result["checked"] == 3
    assert result["dispatched"] == 3
    assert result["skipped"] == 0
    assert result["failed"] == 0


@pytest.mark.asyncio
async def test_backlog_handler_skips_reused_actions(monkeypatch):
    async def _fetch(_session, _batch_size: int):
        return 2, [1, 2]

    actions = iter(["reused_pending", "reused_in_progress"])

    class _FakeService:
        def __init__(self, _session):
            pass

        async def start_transcription(self, _episode_id, force=False):
            assert force is False
            return {"action": next(actions)}

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription._fetch_pending_episode_ids",
        _fetch,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription.DatabaseBackedTranscriptionService",
        _FakeService,
    )

    result = await process_pending_transcriptions_handler(session=object())
    assert result["status"] == "success"
    assert result["dispatched"] == 0
    assert result["skipped"] == 2
    assert result["failed"] == 0
    assert result["skipped_reasons"] == {
        "reused_pending": 1,
        "reused_in_progress": 1,
    }


@pytest.mark.asyncio
async def test_backlog_handler_counts_failures(monkeypatch):
    async def _fetch(_session, _batch_size: int):
        return 2, [1, 2]

    class _FakeService:
        def __init__(self, _session):
            pass

        async def start_transcription(self, episode_id, force=False):
            assert force is False
            if episode_id == 1:
                raise RuntimeError("dispatch failed")
            return {"action": "redispatched_failed_with_temp"}

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription._fetch_pending_episode_ids",
        _fetch,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription.DatabaseBackedTranscriptionService",
        _FakeService,
    )

    result = await process_pending_transcriptions_handler(session=object())
    assert result["status"] == "success"
    assert result["dispatched"] == 1
    assert result["failed"] == 1


@pytest.mark.asyncio
async def test_backlog_handler_respects_feature_toggle(monkeypatch):
    monkeypatch.setattr(settings, "TRANSCRIPTION_BACKLOG_ENABLED", False)
    result = await process_pending_transcriptions_handler(session=object())
    assert result["status"] == "skipped"
    assert result["reason"] == "backlog_transcription_disabled"


def test_process_pending_transcriptions_retries_on_failure(monkeypatch):
    class _RetryError(Exception):
        pass

    def _run_async_raise(coro):
        coro.close()
        raise RuntimeError("boom")

    logs = []

    def _log_task_run(**kwargs):
        logs.append(kwargs)

    task = pending_transcription.process_pending_transcriptions
    monkeypatch.setattr(pending_transcription, "run_async", _run_async_raise)
    monkeypatch.setattr(pending_transcription, "log_task_run", _log_task_run)

    def _retry(*, countdown):
        raise _RetryError(countdown)

    monkeypatch.setattr(task, "retry", _retry)

    with pytest.raises(_RetryError):
        task.run()

    assert logs
    assert logs[-1]["status"] == "failed"
