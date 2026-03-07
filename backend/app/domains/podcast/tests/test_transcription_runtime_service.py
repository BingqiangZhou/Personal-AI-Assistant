from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.domains.podcast.services.transcription_runtime_service import (
    PodcastTranscriptionRuntimeService,
)


class _ScalarOneOrNoneResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _FakeTaskOrchestrationService:
    def __init__(self, db):
        self.db = db
        self.audio_transcription_calls = []

    def enqueue_audio_transcription(self, *, task_id: int, config_db_id: int | None):
        self.audio_transcription_calls.append(
            {"task_id": task_id, "config_db_id": config_db_id}
        )


@pytest.mark.asyncio
async def test_start_transcription_dispatches_via_task_orchestration_service():
    db = AsyncMock()
    db.execute.return_value = _ScalarOneOrNoneResult(None)
    fake_task_service = _FakeTaskOrchestrationService(db)
    service = PodcastTranscriptionRuntimeService(
        db=db,
        task_orchestration_service_factory=lambda session: fake_task_service,
    )
    created_task = SimpleNamespace(id=55)

    with patch(
        "app.domains.podcast.transcription_state.get_transcription_state_manager",
        new=AsyncMock(return_value=AsyncMock()),
    ), patch(
        "app.domains.podcast.transcription.PodcastTranscriptionService.create_transcription_task_record",
        new=AsyncMock(return_value=(created_task, 11)),
    ):
        result = await service.start_transcription(episode_id=77)

    assert result == {"task": created_task, "action": "created"}
    assert fake_task_service.audio_transcription_calls == [
        {"task_id": 55, "config_db_id": 11}
    ]