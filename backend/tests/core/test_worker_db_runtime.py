from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from app.core import database as database_module


class _FakeEngine:
    def __init__(self) -> None:
        self.dispose_calls = 0

    async def dispose(self) -> None:
        self.dispose_calls += 1


class _FakeSession:
    def __init__(self) -> None:
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


class _FakeSessionFactory:
    def __init__(self, sessions: list[_FakeSession]) -> None:
        self.sessions = sessions

    def __call__(self):
        session = _FakeSession()
        self.sessions.append(session)

        @asynccontextmanager
        async def _ctx():
            yield session

        return _ctx()


@pytest.mark.asyncio
async def test_worker_db_session_reuses_runtime_engine_within_same_loop(monkeypatch):
    await database_module.close_worker_db_runtimes()

    created_application_names: list[str] = []
    created_engines: list[_FakeEngine] = []
    created_sessions: list[_FakeSession] = []

    def _fake_create_isolated_session_factory(application_name: str):
        created_application_names.append(application_name)
        engine = _FakeEngine()
        created_engines.append(engine)
        return _FakeSessionFactory(created_sessions), engine

    monkeypatch.setattr(
        database_module,
        "create_isolated_session_factory",
        _fake_create_isolated_session_factory,
    )

    async with database_module.worker_db_session("celery-summary-episode"):
        pass
    async with database_module.worker_db_session("celery-summary-episode"):
        pass

    assert created_application_names == ["celery-summary-episode"]
    assert len(created_sessions) == 2
    assert [session.close_calls for session in created_sessions] == [1, 1]

    await database_module.close_worker_db_runtimes()

    assert created_engines[0].dispose_calls == 1
