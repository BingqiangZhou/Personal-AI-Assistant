"""Summary task flow tests."""

from types import SimpleNamespace

import pytest

from app.core.exceptions import ValidationError
from app.domains.podcast.services.summary_workflow_service import SummaryWorkflowService
from app.domains.podcast.tasks import summary_generation
from app.domains.podcast.tasks.handlers_summary import (
    generate_pending_summaries_handler,
)


class _ScalarResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value

    def scalars(self):
        class _Scalars:
            def __init__(self, value):
                self._value = value

            def all(self):
                if self._value is None:
                    return []
                if isinstance(self._value, list):
                    return self._value
                return [self._value]

        return _Scalars(self._value)


class _FakeSession:
    def __init__(self, values):
        self._values = iter(values)
        self.execute_count = 0

    async def execute(self, _stmt):
        self.execute_count += 1
        return _ScalarResult(next(self._values))


async def _run_workflow(session, repo_factory, summary_factory):
    workflow = SummaryWorkflowService(
        session,
        repo_factory=repo_factory,
        summary_service_factory=summary_factory,
    )
    return await workflow.generate_pending_summaries_run()


@pytest.mark.asyncio
async def test_generate_pending_summaries_success():
    fake_episode = SimpleNamespace(id=11, subscription_id=22, transcript_content="hello")
    marked = []
    generated = []

    class _FakeRepo:
        def __init__(self, _session):
            pass

        async def get_unsummarized_episodes(self, *args, **kwargs):
            return [fake_episode]

        async def mark_summary_failed(self, episode_id, error):
            marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, episode_id):
            generated.append(episode_id)
            return {"summary_content": "ok"}

    session = _FakeSession([[]])
    result = await _run_workflow(session, _FakeRepo, _FakeSummaryService)
    assert result["status"] == "success"
    assert result["processed"] == 1
    assert result["failed"] == 0
    assert marked == []
    assert generated == [11]


@pytest.mark.asyncio
async def test_generate_pending_summaries_skips_missing_transcript_without_failure():
    fake_episode = SimpleNamespace(id=11, subscription_id=22, transcript_content="   ")
    marked = []
    generated = []

    class _FakeRepo:
        def __init__(self, _session):
            pass

        async def get_unsummarized_episodes(self, *args, **kwargs):
            return [fake_episode]

        async def mark_summary_failed(self, episode_id, error):
            marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, episode_id):
            generated.append(episode_id)
            return {"summary_content": "ok"}

    session = _FakeSession([])
    result = await _run_workflow(session, _FakeRepo, _FakeSummaryService)
    assert result["status"] == "success"
    assert result["processed"] == 0
    assert result["failed"] == 0
    assert marked == []
    assert generated == []
    assert session.execute_count == 0


@pytest.mark.asyncio
async def test_generate_pending_summaries_filters_before_limit():
    episodes = []
    for episode_id in range(1, 15):
        transcript = None if episode_id <= 3 else f"transcript-{episode_id}"
        episodes.append(
            SimpleNamespace(
                id=episode_id,
                subscription_id=22,
                transcript_content=transcript,
            )
        )

    marked = []
    generated = []

    class _FakeRepo:
        def __init__(self, _session):
            pass

        async def get_unsummarized_episodes(self, *args, **kwargs):
            return episodes

        async def mark_summary_failed(self, episode_id, error):
            marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, episode_id):
            generated.append(episode_id)
            return {"summary_content": "ok"}

    session = _FakeSession([[]])
    result = await _run_workflow(session, _FakeRepo, _FakeSummaryService)
    assert result["status"] == "success"
    assert result["processed"] == 10
    assert result["failed"] == 0
    assert generated == list(range(4, 14))
    assert marked == []
    assert session.execute_count == 1


@pytest.mark.asyncio
async def test_generate_pending_summaries_no_transcript_validation_does_not_mark_failed():
    fake_episode = SimpleNamespace(id=11, subscription_id=22, transcript_content="ready")
    marked = []

    class _FakeRepo:
        def __init__(self, _session):
            pass

        async def get_unsummarized_episodes(self, *args, **kwargs):
            return [fake_episode]

        async def mark_summary_failed(self, episode_id, error):
            marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, _episode_id):
            raise ValidationError("No transcript content available for episode 11")

    session = _FakeSession([[]])
    result = await _run_workflow(session, _FakeRepo, _FakeSummaryService)
    assert result["status"] == "success"
    assert result["processed"] == 0
    assert result["failed"] == 0
    assert marked == []


@pytest.mark.asyncio
async def test_generate_pending_summaries_non_validation_error_marks_failed():
    fake_episode = SimpleNamespace(id=11, subscription_id=22, transcript_content="ready")
    marked = []

    class _FakeRepo:
        def __init__(self, _session):
            pass

        async def get_unsummarized_episodes(self, *args, **kwargs):
            return [fake_episode]

        async def mark_summary_failed(self, episode_id, error):
            marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, _episode_id):
            raise RuntimeError("boom")

    session = _FakeSession([[]])
    result = await _run_workflow(session, _FakeRepo, _FakeSummaryService)
    assert result["status"] == "success"
    assert result["processed"] == 0
    assert result["failed"] == 1
    assert len(marked) == 1
    assert marked[0][0] == 11
    assert "boom" in marked[0][1]


@pytest.mark.asyncio
async def test_generate_pending_summaries_in_progress_validation_does_not_mark_failed():
    fake_episode = SimpleNamespace(id=11, subscription_id=22, transcript_content="ready")
    marked = []

    class _FakeRepo:
        def __init__(self, _session):
            pass

        async def get_unsummarized_episodes(self, *args, **kwargs):
            return [fake_episode]

        async def mark_summary_failed(self, episode_id, error):
            marked.append((episode_id, error))

    class _FakeSummaryService:
        def __init__(self, _session):
            pass

        async def generate_summary(self, _episode_id):
            raise ValidationError("Summary generation already in progress for episode 11")

    session = _FakeSession([[]])
    result = await _run_workflow(session, _FakeRepo, _FakeSummaryService)
    assert result["status"] == "success"
    assert result["processed"] == 0
    assert result["failed"] == 0
    assert marked == []


@pytest.mark.asyncio
async def test_handler_delegates_to_summary_workflow(monkeypatch):
    class _FakeWorkflow:
        def __init__(self, session):
            self.session = session

        async def generate_pending_summaries_run(self):
            return {"status": "success", "processed": 1, "failed": 0}

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_summary.SummaryWorkflowService",
        _FakeWorkflow,
    )

    result = await generate_pending_summaries_handler(object())
    assert result == {"status": "success", "processed": 1, "failed": 0}


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
