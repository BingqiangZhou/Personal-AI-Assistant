"""Summary task flow tests."""

from types import SimpleNamespace

import pytest

from app.domains.podcast.tasks import summary_generation
from app.domains.podcast.tasks.handlers_summary import (
    generate_pending_summaries_handler,
    generate_summary_for_episode_handler,
)


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeSession:
    def __init__(self, values):
        self._values = iter(values)

    async def execute(self, _stmt):
        return _ScalarResult(next(self._values))


@pytest.mark.asyncio
async def test_generate_pending_summaries_success(monkeypatch):
    fake_episode = SimpleNamespace(id=11, subscription_id=22)

    class _FakeRepo:
        def __init__(self, _session):
            self.marked = []

        async def get_unsummarized_episodes(self):
            return [fake_episode]

        async def mark_summary_failed(self, episode_id, error):
            self.marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, _episode_id):
            return {"summary_content": "ok"}

    session = _FakeSession(
        [
            None,  # No running transcription task
            SimpleNamespace(user_id=7),  # User subscription owner
        ]
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_summary.PodcastRepository",
        _FakeRepo,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_summary.DatabaseBackedAISummaryService",
        _FakeSummaryService,
    )

    result = await generate_pending_summaries_handler(session)
    assert result["status"] == "success"
    assert result["processed"] == 1
    assert result["failed"] == 0


def test_generate_pending_summaries_retries_on_failure(monkeypatch):
    class _RetryError(Exception):
        pass

    def _run_async_raise(coro):
        coro.close()
        raise RuntimeError("summary failed")

    logs = []

    def _log_task_run(**kwargs):
        logs.append(kwargs)

    task = summary_generation.generate_pending_summaries
    monkeypatch.setattr(summary_generation, "run_async", _run_async_raise)
    monkeypatch.setattr(summary_generation, "log_task_run", _log_task_run)

    def _retry(*, countdown):
        raise _RetryError(countdown)

    monkeypatch.setattr(task, "retry", _retry)

    with pytest.raises(_RetryError):
        task.run()

    assert logs
    assert logs[-1]["status"] == "failed"


@pytest.mark.asyncio
async def test_generate_summary_for_episode_handler_uses_db_backed_service(monkeypatch):
    fake_episode = SimpleNamespace(id=99)
    session = _FakeSession([fake_episode])

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, episode_id):
            return {"summary_content": f"summary-{episode_id}"}

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_summary.DatabaseBackedAISummaryService",
        _FakeSummaryService,
    )

    result = await generate_summary_for_episode_handler(
        session=session,
        episode_id=99,
        user_id=7,
    )
    assert result["status"] == "success"
    assert result["episode_id"] == 99
    assert result["summary"] == "summary-99"
