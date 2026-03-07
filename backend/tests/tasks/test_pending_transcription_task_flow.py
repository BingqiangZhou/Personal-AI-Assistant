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

    class _FakeWorkflow:
        def __init__(self, _session):
            pass

        async def dispatch_pending_transcriptions(self, episode_ids):
            assert episode_ids == [101, 102, 103]
            return {
                "checked": 3,
                "dispatched": 3,
                "skipped": 0,
                "failed": 0,
                "skipped_reasons": {},
            }

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription._fetch_pending_episode_ids",
        _fetch,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription.TranscriptionWorkflowService",
        _FakeWorkflow,
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

    class _FakeWorkflow:
        def __init__(self, _session):
            pass

        async def dispatch_pending_transcriptions(self, episode_ids):
            assert episode_ids == [1, 2]
            return {
                "checked": 2,
                "dispatched": 0,
                "skipped": 2,
                "failed": 0,
                "skipped_reasons": {
                    "reused_pending": 1,
                    "reused_in_progress": 1,
                },
            }

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription._fetch_pending_episode_ids",
        _fetch,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription.TranscriptionWorkflowService",
        _FakeWorkflow,
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

    class _FakeWorkflow:
        def __init__(self, _session):
            pass

        async def dispatch_pending_transcriptions(self, episode_ids):
            assert episode_ids == [1, 2]
            return {
                "checked": 2,
                "dispatched": 1,
                "skipped": 0,
                "failed": 1,
                "skipped_reasons": {},
            }

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription._fetch_pending_episode_ids",
        _fetch,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_pending_transcription.TranscriptionWorkflowService",
        _FakeWorkflow,
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
