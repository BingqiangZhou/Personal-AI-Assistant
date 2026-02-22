from datetime import datetime, timezone
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from app.domains.podcast.api.dependencies import get_podcast_service
from app.domains.podcast.api.routes_episodes import (
    _encode_keyset_cursor,
    _encode_page_cursor,
)
from app.main import app


def _sample_episode(now: datetime) -> dict:
    return {
        "id": 1,
        "subscription_id": 1,
        "title": "Episode 1",
        "description": "desc",
        "audio_url": "https://example.com/audio.mp3",
        "audio_duration": 1200,
        "published_at": now,
        "play_count": 0,
        "is_playing": False,
        "playback_rate": 1.0,
        "is_played": False,
        "status": "published",
        "created_at": now,
        "updated_at": now,
    }


def test_feed_legacy_page_cursor_compatible():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    now = datetime.now(timezone.utc)
    service.list_episodes.return_value = ([_sample_episode(now)], 25)
    page_cursor = _encode_page_cursor(2)

    response = client.get(
        f"/api/v1/podcasts/episodes/feed?cursor={page_cursor}&page_size=10"
    )

    assert response.status_code == 200
    service.list_episodes.assert_awaited_once_with(filters=None, page=2, size=10)

    app.dependency_overrides.pop(get_podcast_service, None)


def test_feed_accepts_size_alias():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    now = datetime.now(timezone.utc)
    service.list_episodes.return_value = ([_sample_episode(now)], 25)

    response = client.get("/api/v1/podcasts/episodes/feed?page=2&size=11")

    assert response.status_code == 200
    service.list_episodes.assert_awaited_once_with(filters=None, page=2, size=11)

    app.dependency_overrides.pop(get_podcast_service, None)


def test_feed_keyset_cursor_path():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    now = datetime.now(timezone.utc)
    service.get_feed_by_cursor.return_value = (
        [_sample_episode(now)],
        100,
        True,
        (now, 1),
    )
    keyset_cursor = _encode_keyset_cursor("feed", now, 999)

    response = client.get(
        f"/api/v1/podcasts/episodes/feed?cursor={keyset_cursor}&page_size=10"
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["has_more"] is True
    assert payload["next_cursor"]
    service.get_feed_by_cursor.assert_awaited_once()

    app.dependency_overrides.pop(get_podcast_service, None)


def test_history_keyset_cursor_path():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    now = datetime.now(timezone.utc)
    service.get_playback_history_by_cursor.return_value = (
        [_sample_episode(now)],
        20,
        True,
        (now, 1),
    )
    keyset_cursor = _encode_keyset_cursor("history", now, 888)

    response = client.get(
        f"/api/v1/podcasts/episodes/history?cursor={keyset_cursor}&size=10"
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["next_cursor"]
    service.get_playback_history_by_cursor.assert_awaited_once()

    app.dependency_overrides.pop(get_podcast_service, None)


def test_search_accepts_query_alias():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    now = datetime.now(timezone.utc)
    service.search_podcasts.return_value = ([_sample_episode(now)], 1)

    response = client.get("/api/v1/podcasts/search?query=daily")

    assert response.status_code == 200
    service.search_podcasts.assert_awaited_once_with(
        query="daily",
        search_in="all",
        page=1,
        size=20,
    )

    app.dependency_overrides.pop(get_podcast_service, None)


def test_search_prefers_q_when_both_q_and_query_present():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    now = datetime.now(timezone.utc)
    service.search_podcasts.return_value = ([_sample_episode(now)], 1)

    response = client.get("/api/v1/podcasts/search?q=fast&query=slow")

    assert response.status_code == 200
    service.search_podcasts.assert_awaited_once_with(
        query="fast",
        search_in="all",
        page=1,
        size=20,
    )

    app.dependency_overrides.pop(get_podcast_service, None)


def test_search_requires_q_or_query():
    service = AsyncMock()
    app.dependency_overrides[get_podcast_service] = lambda: service
    client = TestClient(app)

    response = client.get("/api/v1/podcasts/search")

    assert response.status_code == 422
    service.search_podcasts.assert_not_awaited()

    app.dependency_overrides.pop(get_podcast_service, None)
