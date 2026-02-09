"""Unit tests for podcast queue service."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from app.domains.podcast.services.queue_service import PodcastQueueService


@pytest.fixture
def mock_db():
    return AsyncMock()


@pytest.fixture
def mock_repo():
    with patch("app.domains.podcast.services.queue_service.PodcastRepository") as mock:
        repo_instance = AsyncMock()
        mock.return_value = repo_instance
        yield repo_instance


@pytest.fixture
def service(mock_db, mock_repo):
    return PodcastQueueService(mock_db, user_id=1)


def _queue_snapshot(current_episode_id: int | None = 10):
    episode = SimpleNamespace(
        title="Episode 10",
        subscription_id=2,
        audio_url="https://example.com/audio.mp3",
        audio_duration=1800,
        published_at=None,
        image_url=None,
        subscription=SimpleNamespace(
            title="Podcast A", config={"image_url": "https://example.com/cover.png"}
        ),
    )
    item = SimpleNamespace(id=1, episode_id=10, position=0, episode=episode)
    return SimpleNamespace(
        current_episode_id=current_episode_id,
        revision=3,
        updated_at=None,
        items=[item],
    )


@pytest.mark.asyncio
async def test_get_queue_serializes_snapshot(service, mock_repo):
    mock_repo.get_queue_with_items.return_value = _queue_snapshot()

    result = await service.get_queue()

    assert result["current_episode_id"] == 10
    assert result["revision"] == 3
    assert len(result["items"]) == 1
    assert result["items"][0]["episode_id"] == 10
    assert result["items"][0]["title"] == "Episode 10"


@pytest.mark.asyncio
async def test_add_to_queue_requires_accessible_episode(service, mock_repo):
    mock_repo.get_episode_by_id.return_value = None

    with pytest.raises(ValueError, match="EPISODE_NOT_FOUND"):
        await service.add_to_queue(999)


@pytest.mark.asyncio
async def test_reorder_queue_propagates_payload(service, mock_repo):
    mock_repo.reorder_items.return_value = _queue_snapshot()

    await service.reorder_queue([10])

    mock_repo.reorder_items.assert_called_once_with(1, [10])
