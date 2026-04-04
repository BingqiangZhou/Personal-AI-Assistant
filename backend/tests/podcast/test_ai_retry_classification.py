from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.core.ai_client import is_retryable_http_status as unified_retryable
from app.domains.ai.services.model_runtime_service import (
    _is_retryable_http_status as runtime_retryable,
)
from app.domains.podcast.services import summary_generation_service as summary_module
from app.domains.podcast.services.summary_service import (
    SummaryModelManager,
)
from app.domains.podcast.services.summary_service import (
    _is_retryable_http_status as summary_retryable,
)


def test_unified_retryable_status_classification() -> None:
    """The unified is_retryable_http_status covers all known retryable codes."""
    assert unified_retryable(500) is True
    assert unified_retryable(503) is True
    assert unified_retryable(429) is True
    assert unified_retryable(408) is True
    assert unified_retryable(409) is True
    assert unified_retryable(425) is True
    assert unified_retryable(401) is False
    assert unified_retryable(400) is False
    assert unified_retryable(404) is False


def test_runtime_retryable_status_matches_unified() -> None:
    """Runtime service and unified client must agree on retryable status codes."""
    for code in [500, 429, 408, 409, 425, 401, 400, 404]:
        assert runtime_retryable(code) == unified_retryable(code), (
            f"Mismatch for status {code}"
        )


def test_summary_retryable_status_classification() -> None:
    assert summary_retryable(503) is True
    assert summary_retryable(425) is True
    assert summary_retryable(409) is True
    assert summary_retryable(404) is False


@pytest.mark.asyncio
async def test_summary_retry_retries_only_transient_errors(monkeypatch) -> None:
    manager = SummaryModelManager(db=AsyncMock())
    manager.ai_model_repo.increment_usage = AsyncMock()
    model_config = SimpleNamespace(id=1, name="summary-model", provider="openai")

    attempts = 0

    async def _always_retryable_fail(**_kwargs):
        nonlocal attempts
        attempts += 1
        raise summary_module.RetryableSummaryModelError("transient")

    sleep_mock = AsyncMock()
    monkeypatch.setattr(summary_module.asyncio, "sleep", sleep_mock)
    manager._call_ai_api = _always_retryable_fail

    with pytest.raises(Exception, match="failed after 3 attempts"):
        await manager._call_ai_api_with_retry(
            model_config=model_config,
            api_key="k",
            prompt="p",
            episode_info={},
        )

    assert attempts == 3
    assert sleep_mock.await_count == 2
    assert manager.ai_model_repo.increment_usage.await_count == 3


@pytest.mark.asyncio
async def test_summary_retry_does_not_retry_non_transient_errors(monkeypatch) -> None:
    manager = SummaryModelManager(db=AsyncMock())
    manager.ai_model_repo.increment_usage = AsyncMock()
    model_config = SimpleNamespace(id=1, name="summary-model", provider="openai")

    attempts = 0

    async def _non_retryable_fail(**_kwargs):
        nonlocal attempts
        attempts += 1
        raise summary_module.HTTPException(status_code=500, detail="bad request")

    sleep_mock = AsyncMock()
    monkeypatch.setattr(summary_module.asyncio, "sleep", sleep_mock)
    manager._call_ai_api = _non_retryable_fail

    with pytest.raises(Exception, match="failed without retry"):
        await manager._call_ai_api_with_retry(
            model_config=model_config,
            api_key="k",
            prompt="p",
            episode_info={},
        )

    assert attempts == 1
    sleep_mock.assert_not_awaited()
    manager.ai_model_repo.increment_usage.assert_awaited_once()
