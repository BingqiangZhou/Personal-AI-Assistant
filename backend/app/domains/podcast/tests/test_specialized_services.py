"""
单元测试 - Podcast专业化服务

Unit tests for Podcast specialized services
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.core.config import settings
from app.domains.podcast.services import (
    PodcastEpisodeService,
    PodcastPlaybackService,
    PodcastSearchService,
    PodcastSubscriptionService,
    PodcastSyncService,
)


class TestPodcastSubscriptionService:
    """测试播客订阅服务"""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        with patch(
            "app.domains.podcast.services.subscription_service.PodcastRepository"
        ) as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_redis(self):
        with patch(
            "app.domains.podcast.services.subscription_service.PodcastRedis"
        ) as mock:
            redis_instance = AsyncMock()
            mock.return_value = redis_instance
            yield redis_instance

    @pytest.fixture
    def mock_parser(self):
        with patch(
            "app.domains.podcast.services.subscription_service.SecureRSSParser"
        ) as mock:
            parser_instance = AsyncMock()
            mock.return_value = parser_instance
            yield parser_instance

    @pytest.fixture
    def service(self, mock_db, mock_repo, mock_redis, mock_parser):
        return PodcastSubscriptionService(mock_db, user_id=1)

    @pytest.mark.asyncio
    async def test_service_initialization(self, service):
        """测试服务初始化"""
        assert service.user_id == 1
        assert service.db is not None
        assert service.repo is not None
        assert service.redis is not None
        assert service.parser is not None

    @pytest.mark.asyncio
    async def test_list_subscriptions_empty(self, service, mock_repo):
        """测试空订阅列表"""
        mock_repo.get_user_subscriptions_paginated.return_value = ([], 0, {})
        mock_repo.get_episodes_counts_batch.return_value = {}
        mock_repo.get_subscription_episodes_batch.return_value = {}
        mock_repo.get_playback_states_batch.return_value = {}

        results, total = await service.list_subscriptions()

        assert results == []
        assert total == 0
        mock_repo.get_user_subscriptions_paginated.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_subscriptions_cache_hit(self, service, mock_repo, mock_redis):
        """Cached subscription list should short-circuit repository calls."""
        cached_payload = {
            "subscriptions": [
                {
                    "id": 1,
                    "title": "cached",
                    "source_url": "https://example.com/feed.xml",
                }
            ],
            "total": 1,
        }
        mock_redis.get_subscription_list.return_value = cached_payload

        results, total = await service.list_subscriptions(page=1, size=20)

        assert results == cached_payload["subscriptions"]
        assert total == 1
        mock_redis.get_subscription_list.assert_awaited_once()
        mock_repo.get_user_subscriptions_paginated.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_subscription_details_not_found(self, service, mock_repo):
        """测试获取不存在的订阅详情"""
        mock_repo.get_subscription_by_id.return_value = None

        result = await service.get_subscription_details(999)

        assert result is None
        mock_repo.get_subscription_by_id.assert_called_once()


class TestPodcastEpisodeService:
    """测试播客单集服务"""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        with patch(
            "app.domains.podcast.services.episode_service.PodcastRepository"
        ) as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_redis(self):
        with patch("app.domains.podcast.services.episode_service.PodcastRedis") as mock:
            redis_instance = AsyncMock()
            mock.return_value = redis_instance
            yield redis_instance

    @pytest.fixture
    def service(self, mock_db, mock_repo, mock_redis):
        return PodcastEpisodeService(mock_db, user_id=1)

    @pytest.mark.asyncio
    async def test_service_initialization(self, service):
        """测试服务初始化"""
        assert service.user_id == 1
        assert service.db is not None
        assert service.repo is not None
        assert service.redis is not None

    @pytest.mark.asyncio
    async def test_get_episode_by_id(self, service, mock_repo):
        """测试获取单集详情"""
        mock_episode = Mock()
        mock_episode.id = 1
        mock_repo.get_episode_by_id.return_value = mock_episode

        result = await service.get_episode_by_id(1)

        assert result == mock_episode
        mock_repo.get_episode_by_id.assert_called_once_with(1, 1)

    @pytest.mark.asyncio
    async def test_feed_page_lightweight_prefers_one_line_summary(
        self, service, mock_repo, monkeypatch
    ):
        monkeypatch.setattr(settings, "PODCAST_FEED_LIGHTWEIGHT_ENABLED", True)
        mock_repo.get_feed_lightweight_page_paginated.return_value = (
            [
                {
                    "id": 1,
                    "description": "fallback description",
                    "ai_summary": (
                        "## Executive Summary\n"
                        "A concise summary sentence.\n\n"
                        "## Key Insights\n"
                        "More details."
                    ),
                    "transcript_content": "transcript",
                }
            ],
            1,
        )

        results, total = await service.list_feed_by_page(page=1, size=20)

        assert total == 1
        assert results[0]["description"] == "A concise summary sentence."
        assert results[0]["ai_summary"] is None
        assert results[0]["transcript_content"] is None

    @pytest.mark.asyncio
    async def test_feed_cursor_lightweight_falls_back_to_collapsed_description(
        self, service, mock_repo, monkeypatch
    ):
        monkeypatch.setattr(settings, "PODCAST_FEED_LIGHTWEIGHT_ENABLED", True)
        raw_description = "   Fallback   text \n with   extra   spaces   "
        mock_repo.get_feed_lightweight_cursor_paginated.return_value = (
            [
                {
                    "id": 1,
                    "description": raw_description,
                    "ai_summary": None,
                    "transcript_content": "transcript",
                }
            ],
            1,
            False,
            None,
        )

        results, total, has_more, next_cursor = await service.list_feed_by_cursor(
            size=20
        )

        assert total == 1
        assert has_more is False
        assert next_cursor is None
        assert results[0]["description"] == "Fallback text with extra spaces"
        assert results[0]["ai_summary"] is None
        assert results[0]["transcript_content"] is None

    @pytest.mark.asyncio
    async def test_feed_page_non_lightweight_rewrites_description_only_for_feed(
        self, service, mock_repo, monkeypatch
    ):
        monkeypatch.setattr(settings, "PODCAST_FEED_LIGHTWEIGHT_ENABLED", False)
        now = datetime.now(timezone.utc)
        episode = _build_mock_episode(
            description="Original fallback description",
            ai_summary=(
                "## Executive Summary\n"
                "Feed summary line.\n\n"
                "## Key Insights\n"
                "More details."
            ),
            created_at=now,
            published_at=now,
        )
        mock_repo.get_episodes_paginated.return_value = ([episode], 1)
        mock_repo.get_playback_states_batch.return_value = {}

        results, total = await service.list_feed_by_page(page=1, size=20)

        assert total == 1
        assert results[0]["description"] == "Feed summary line."
        assert "Executive Summary" in (results[0]["ai_summary"] or "")

    @pytest.mark.asyncio
    async def test_list_episodes_keeps_original_description(self, service, mock_repo):
        now = datetime.now(timezone.utc)
        episode = _build_mock_episode(
            description="Original episode description",
            ai_summary=(
                "## Executive Summary\n"
                "Should not replace non-feed description.\n\n"
                "## Details\n"
                "More details."
            ),
            created_at=now,
            published_at=now,
        )
        mock_repo.get_episodes_paginated.return_value = ([episode], 1)
        mock_repo.get_playback_states_batch.return_value = {}

        results, total = await service.list_episodes(page=1, size=20)

        assert total == 1
        assert results[0]["description"] == "Original episode description"

    def test_resolve_feed_description_truncates_fallback(self, service):
        long_description = "a" * 500

        result = service._resolve_feed_description(
            ai_summary=None,
            fallback_description=long_description,
        )

        assert result is not None
        assert len(result) == service._feed_description_max_length


class TestPodcastPlaybackService:
    """测试播客播放服务"""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        with patch(
            "app.domains.podcast.services.playback_service.PodcastRepository"
        ) as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def service(self, mock_db, mock_repo):
        return PodcastPlaybackService(mock_db, user_id=1)

    @pytest.mark.asyncio
    async def test_service_initialization(self, service):
        """测试服务初始化"""
        assert service.user_id == 1
        assert service.db is not None
        assert service.repo is not None

    @pytest.mark.asyncio
    async def test_get_playback_state_not_found(self, service, mock_repo):
        """测试获取不存在的播放状态"""
        mock_repo.get_playback_state.return_value = None
        mock_repo.get_episode_by_id.return_value = None

        result = await service.get_playback_state(1)

        assert result is None


class TestPodcastSearchService:
    """测试播客搜索服务"""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        with patch(
            "app.domains.podcast.services.search_service.PodcastRepository"
        ) as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_redis(self):
        with patch("app.domains.podcast.services.search_service.PodcastRedis") as mock:
            redis_instance = AsyncMock()
            mock.return_value = redis_instance
            yield redis_instance

    @pytest.fixture
    def service(self, mock_db, mock_repo, mock_redis):
        return PodcastSearchService(mock_db, user_id=1)

    @pytest.mark.asyncio
    async def test_service_initialization(self, service):
        """测试服务初始化"""
        assert service.user_id == 1
        assert service.db is not None
        assert service.repo is not None
        assert service.redis is not None

    @pytest.mark.asyncio
    async def test_search_podcasts_empty(self, service, mock_repo, mock_redis):
        """测试空搜索结果"""
        mock_repo.search_episodes.return_value = ([], 0)
        mock_redis.get_search_results.return_value = None
        mock_repo.get_playback_states_batch.return_value = {}

        results, total = await service.search_podcasts("test query")

        assert results == []
        assert total == 0

    @pytest.mark.asyncio
    async def test_get_recommendations_empty(self, service, mock_repo):
        """测试空推荐结果"""
        mock_repo.get_liked_episodes.return_value = []

        results = await service.get_recommendations(limit=10)

        assert results == []


class TestPodcastSyncService:
    """测试播客同步服务"""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        with patch(
            "app.domains.podcast.services.sync_service.PodcastRepository"
        ) as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def service(self, mock_db, mock_repo):
        return PodcastSyncService(mock_db, user_id=1)

    @pytest.mark.asyncio
    async def test_service_initialization(self, service):
        """测试服务初始化"""
        assert service.user_id == 1
        assert service.db is not None
        assert service.repo is not None


def _build_mock_episode(
    *,
    description: str,
    ai_summary: str | None,
    created_at: datetime,
    published_at: datetime,
) -> Mock:
    episode = Mock()
    episode.id = 1
    episode.subscription_id = 1
    episode.subscription = None
    episode.title = "Episode title"
    episode.description = description
    episode.audio_url = "https://example.com/audio.mp3"
    episode.audio_duration = 120
    episode.audio_file_size = 1024
    episode.published_at = published_at
    episode.image_url = None
    episode.item_link = None
    episode.transcript_url = None
    episode.transcript_content = None
    episode.ai_summary = ai_summary
    episode.summary_version = "1.0"
    episode.ai_confidence_score = 0.9
    episode.play_count = 0
    episode.last_played_at = None
    episode.season = None
    episode.episode_number = None
    episode.explicit = False
    episode.status = "published"
    episode.metadata_json = {}
    episode.created_at = created_at
    episode.updated_at = created_at
    return episode
