from unittest.mock import AsyncMock

import pytest

from app.core.redis import PodcastRedis


class _FakeRedisClient:
    def __init__(
        self, *, fail_ping: bool = False, hgetall_data: dict[str, str] | None = None
    ) -> None:
        self.fail_ping = fail_ping
        self.hgetall_data = hgetall_data or {}
        self.ping_calls = 0
        self.get_calls = 0
        self.close_calls = 0
        self.set_calls: list[tuple[str, str, int, bool]] = []
        self.hgetall_calls: list[str] = []
        self.hget_calls: list[tuple[str, str]] = []

    async def ping(self) -> None:
        self.ping_calls += 1
        if self.fail_ping:
            raise RuntimeError("ping failed")

    async def get(self, _key: str) -> str:
        self.get_calls += 1
        return "cached-value"

    async def set(self, key: str, value: str, ex: int, nx: bool) -> bool:
        self.set_calls.append((key, value, ex, nx))
        return True

    async def hgetall(self, key: str) -> dict[str, str]:
        self.hgetall_calls.append(key)
        return self.hgetall_data

    async def hget(self, key: str, field: str) -> str | None:
        self.hget_calls.append((key, field))
        return None

    async def close(self) -> None:
        self.close_calls += 1


@pytest.mark.asyncio
async def test_cache_get_skips_ping_within_health_check_interval(monkeypatch):
    redis = PodcastRedis()
    client = _FakeRedisClient()
    monkeypatch.setattr(redis, "_build_client", lambda: client)

    assert await redis.cache_get("podcast:test:1") == "cached-value"
    assert client.ping_calls == 1
    assert client.get_calls == 1

    monkeypatch.setattr(
        "app.core.redis.perf_counter",
        lambda: redis._last_health_check_at + 1.0,
    )
    assert await redis.cache_get("podcast:test:1") == "cached-value"
    assert client.ping_calls == 1
    assert client.get_calls == 2


@pytest.mark.asyncio
async def test_get_client_reconnects_when_periodic_ping_fails(monkeypatch):
    redis = PodcastRedis()
    first_client = _FakeRedisClient()
    second_client = _FakeRedisClient()

    monkeypatch.setattr(redis, "_build_client", lambda: first_client)
    assert await redis._get_client() is first_client
    assert first_client.ping_calls == 1

    first_client.fail_ping = True
    monkeypatch.setattr(
        "app.core.redis.perf_counter",
        lambda: redis._last_health_check_at + redis._health_check_interval_seconds + 1,
    )
    monkeypatch.setattr(redis, "_build_client", lambda: second_client)

    assert await redis._get_client() is second_client
    assert first_client.ping_calls == 2
    assert second_client.ping_calls == 1


@pytest.mark.asyncio
async def test_get_episode_metadata_reads_hash_with_hgetall():
    redis = PodcastRedis()
    client = _FakeRedisClient(hgetall_data={"id": "7", "title": "hello"})
    redis._get_client = AsyncMock(return_value=client)

    metadata = await redis.get_episode_metadata(7)

    assert metadata == {"id": "7", "title": "hello"}
    assert client.hgetall_calls == ["podcast:meta:7"]
    assert client.hget_calls == []


@pytest.mark.asyncio
async def test_get_client_rebuilds_client_when_event_loop_token_changes(monkeypatch):
    redis = PodcastRedis()
    first_client = _FakeRedisClient()
    second_client = _FakeRedisClient()
    built_clients = iter([first_client, second_client])
    loop_tokens = iter([100, 200])

    monkeypatch.setattr(redis, "_build_client", lambda: next(built_clients))
    monkeypatch.setattr(redis, "_current_loop_token", lambda: next(loop_tokens))

    assert await redis._get_client() is first_client
    assert await redis._get_client() is second_client
    assert first_client.close_calls == 1
    assert second_client.ping_calls == 1


@pytest.mark.asyncio
async def test_acquire_lock_accepts_custom_value():
    redis = PodcastRedis()
    client = _FakeRedisClient()
    redis._get_client = AsyncMock(return_value=client)

    acquired = await redis.acquire_lock("transcription:episode:42", expire=60, value="task:77")

    assert acquired is True
    assert client.set_calls == [
        ("podcast:lock:transcription:episode:42", "task:77", 60, True)
    ]
