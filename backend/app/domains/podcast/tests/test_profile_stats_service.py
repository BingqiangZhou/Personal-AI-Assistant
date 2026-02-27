from unittest.mock import AsyncMock

import pytest

from app.domains.podcast.services.stats_service import PodcastStatsService


@pytest.mark.asyncio
async def test_get_profile_stats_returns_repo_payload_when_cache_miss():
    service = PodcastStatsService(db=AsyncMock(), user_id=1)
    service.redis = AsyncMock()
    service.repo = AsyncMock()

    service.redis.get_profile_stats.return_value = None
    service.repo.get_profile_stats_aggregated.return_value = {
        "total_subscriptions": 2,
        "total_episodes": 10,
        "summaries_generated": 4,
        "pending_summaries": 6,
        "played_episodes": 3,
        "latest_daily_report_date": None,
    }

    result = await service.get_profile_stats()

    assert result["played_episodes"] == 3
    service.repo.get_profile_stats_aggregated.assert_awaited_once_with(1)
    service.redis.set_profile_stats.assert_awaited_once_with(1, result)


@pytest.mark.asyncio
async def test_get_profile_stats_uses_cache_when_available():
    service = PodcastStatsService(db=AsyncMock(), user_id=2)
    service.redis = AsyncMock()
    service.repo = AsyncMock()

    cached = {
        "total_subscriptions": 9,
        "total_episodes": 90,
        "summaries_generated": 70,
        "pending_summaries": 20,
        "played_episodes": 55,
        "latest_daily_report_date": None,
    }
    service.redis.get_profile_stats.return_value = cached

    result = await service.get_profile_stats()

    assert result == cached
    service.repo.get_profile_stats_aggregated.assert_not_called()
