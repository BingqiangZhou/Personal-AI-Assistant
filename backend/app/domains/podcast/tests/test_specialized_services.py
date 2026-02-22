"""
单元测试 - Podcast专业化服务

Unit tests for Podcast specialized services
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

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
        with patch('app.domains.podcast.services.subscription_service.PodcastRepository') as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_redis(self):
        with patch('app.domains.podcast.services.subscription_service.PodcastRedis') as mock:
            redis_instance = AsyncMock()
            mock.return_value = redis_instance
            yield redis_instance

    @pytest.fixture
    def mock_parser(self):
        with patch('app.domains.podcast.services.subscription_service.SecureRSSParser') as mock:
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
        mock_repo.get_user_subscriptions_paginated.return_value = ([], 0)
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
        with patch('app.domains.podcast.services.episode_service.PodcastRepository') as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_redis(self):
        with patch('app.domains.podcast.services.episode_service.PodcastRedis') as mock:
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


class TestPodcastPlaybackService:
    """测试播客播放服务"""

    @pytest.fixture
    def mock_db(self):
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        with patch('app.domains.podcast.services.playback_service.PodcastRepository') as mock:
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
        with patch('app.domains.podcast.services.search_service.PodcastRepository') as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_redis(self):
        with patch('app.domains.podcast.services.search_service.PodcastRedis') as mock:
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
        with patch('app.domains.podcast.services.sync_service.PodcastRepository') as mock:
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
