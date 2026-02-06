"""Transcription task flow tests."""

from types import SimpleNamespace

import pytest

from app.domains.podcast.tasks import transcription
from app.domains.podcast.tasks.handlers_transcription import (
    process_audio_transcription_handler,
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

    async def refresh(self, _obj):
        return None


class _FakeStateManager:
    def __init__(self, lock_ok: bool = True):
        self.lock_ok = lock_ok
        self.progress_updates: list[tuple[int, str, int, str]] = []
        self.cleared: list[tuple[int, int]] = []
        self.released: list[tuple[int, int]] = []

    async def acquire_task_lock(self, _episode_id, _task_id, expire_seconds=3600):
        return self.lock_ok

    async def is_episode_locked(self, _episode_id):
        return 999

    async def set_task_progress(self, task_id, status, progress, message):
        self.progress_updates.append((task_id, status, progress, message))

    async def clear_task_state(self, task_id, episode_id):
        self.cleared.append((task_id, episode_id))

    async def fail_task_state(self, _task_id, _episode_id, _error):
        return None

    async def release_task_lock(self, episode_id, task_id):
        self.released.append((episode_id, task_id))


@pytest.mark.asyncio
async def test_transcription_handler_lock_conflict(monkeypatch):
    fake_task = SimpleNamespace(id=10, episode_id=20)
    session = _FakeSession([fake_task])
    state = _FakeStateManager(lock_ok=False)

    async def _claim(_task_id: int) -> bool:
        return True

    async def _get_state():
        return state

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_transcription._claim_dispatched",
        _claim,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_transcription.get_transcription_state_manager",
        _get_state,
    )

    result = await process_audio_transcription_handler(session=session, task_id=10)
    assert result["status"] == "skipped"
    assert result["reason"] == "episode_locked"
    assert result["locked_by"] == 999


@pytest.mark.asyncio
async def test_transcription_handler_updates_status_and_releases_lock(monkeypatch):
    fake_task = SimpleNamespace(id=1, episode_id=2)
    session = _FakeSession([fake_task])
    state = _FakeStateManager(lock_ok=True)

    class _FakeService:
        def __init__(self, _session):
            self._update_task_progress_with_session = self._default_update

        async def _default_update(self, *_args, **_kwargs):
            return None

        async def execute_transcription_task(self, task_id, db_session, _config_db_id):
            await self._update_task_progress_with_session(
                db_session,
                task_id,
                "in_progress",
                50,
                "halfway",
            )

    async def _claim(_task_id: int) -> bool:
        return True

    async def _get_state():
        return state

    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_transcription._claim_dispatched",
        _claim,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_transcription.get_transcription_state_manager",
        _get_state,
    )
    monkeypatch.setattr(
        "app.domains.podcast.tasks.handlers_transcription.DatabaseBackedTranscriptionService",
        _FakeService,
    )

    result = await process_audio_transcription_handler(session=session, task_id=1)
    assert result["status"] == "success"
    assert (1, "pending", 0, "Worker starting transcription process...") in state.progress_updates
    assert (1, "in_progress", 50, "halfway") in state.progress_updates
    assert state.cleared == [(1, 2)]
    assert state.released == [(2, 1)]


def test_transcription_task_retries_on_failure(monkeypatch):
    class _RetryError(Exception):
        pass

    def _run_async_raise(coro):
        coro.close()
        raise RuntimeError("boom")

    logs = []

    def _log_task_run(**kwargs):
        logs.append(kwargs)

    task = transcription.process_audio_transcription
    monkeypatch.setattr(transcription, "run_async", _run_async_raise)
    monkeypatch.setattr(transcription, "log_task_run", _log_task_run)

    def _retry(*, countdown):
        raise _RetryError(countdown)

    monkeypatch.setattr(task, "retry", _retry)

    with pytest.raises(_RetryError):
        task.run(task_id=123, config_db_id=None)

    assert logs
    assert logs[-1]["status"] == "failed"
