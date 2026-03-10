import os
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.domains.ai.services.model_runtime_service import AIModelRuntimeService


class _SuccessfulResponse:
    status = 200

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

    async def json(self):
        return {"text": "transcribed text"}

    async def text(self):
        return ""


class _InspectingClientSession:
    def __init__(self):
        self.file_closed_during_post = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False

    def post(self, api_endpoint, headers=None, data=None):
        del api_endpoint, headers
        payload = data()
        for part, *_ in getattr(payload, "_parts", []):
            value = getattr(part, "_value", None)
            if hasattr(value, "closed"):
                self.file_closed_during_post = value.closed
                break
        return _SuccessfulResponse()


@pytest.mark.asyncio
async def test_call_transcription_model_keeps_file_handle_open(monkeypatch):
    fake_session = _InspectingClientSession()
    monkeypatch.setattr("aiohttp.ClientSession", lambda timeout=None: fake_session)

    runtime_service = AIModelRuntimeService(
        repo=AsyncMock(),
        security_service=AsyncMock(get_decrypted_api_key=AsyncMock(return_value="sk-test")),
    )
    model = SimpleNamespace(
        timeout_seconds=30,
        model_id="whisper-1",
        provider="openai",
        api_url="https://example.com",
        name="OpenAI Whisper",
    )

    with TemporaryDirectory() as temp_dir:
        audio_path = os.path.join(temp_dir, "audio.mp3")
        with open(audio_path, "wb") as file_obj:
            file_obj.write(b"fake audio bytes")

        result = await runtime_service._call_transcription_model(model, audio_path)

    assert result == "transcribed text"
    assert fake_session.file_closed_during_post is False
