"""
播客服务层测试用例
"""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.domains.podcast.services import PodcastService


class TestPodcastService:
    """播客服务测试"""

    @pytest.fixture
    def mock_db(self):
        """模拟数据库会话"""
        return AsyncMock()

    @pytest.fixture
    def mock_repo(self):
        """模拟仓储层"""
        with patch('app.domains.podcast.repositories.PodcastRepository') as mock:
            repo_instance = AsyncMock()
            mock.return_value = repo_instance
            yield repo_instance

    @pytest.fixture
    def mock_parser(self):
        """模拟RSS解析器"""
        with patch('app.integration.podcast.secure_rss_parser.SecureRSSParser') as mock:
            parser_instance = AsyncMock()
            mock.return_value = parser_instance
            yield parser_instance

    @pytest.fixture
    def mock_redis(self):
        """模拟Redis"""
        with patch('app.core.redis.PodcastRedis') as mock:
            redis_instance = AsyncMock()
            mock.return_value = redis_instance
            yield redis_instance

    @pytest.fixture
    def podcast_service(self, mock_db, mock_repo, mock_parser, mock_redis):
        """创建播客服务实例"""
        # Patch the SecureRSSParser in subscription_service
        with patch('app.domains.podcast.services.subscription_service.SecureRSSParser', return_value=mock_parser):
            service = PodcastService(mock_db, user_id=1)
            service.repo = mock_repo
            service.redis = mock_redis
            return service

    @pytest.mark.asyncio
    async def test_add_subscription_success(self, podcast_service, mock_repo, mock_parser):
        """测试成功添加订阅"""
        # 准备测试数据
        feed_url = "https://example.com/podcast.rss"
        custom_name = "测试播客"

        # 模拟RSS解析结果
        mock_feed = Mock()
        mock_feed.title = "原始播客名称"
        mock_feed.description = "播客描述"
        mock_feed.episodes = [Mock() for _ in range(5)]  # 5个单集

        for i, episode in enumerate(mock_feed.episodes):
            episode.guid = f"episode-{i}"
            episode.title = f"单集{i+1}"
            episode.description = f"单集{i+1}描述"
            episode.audio_url = f"https://example.com/ep{i+1}.mp3"
            episode.published_at = datetime.utcnow()
            episode.duration = 1800
            episode.transcript_url = None

        mock_parser.fetch_and_parse_feed.return_value = (True, mock_feed, None)

        # 模拟订阅创建
        mock_subscription = Mock()
        mock_subscription.id = 1
        mock_subscription.user_id = 1
        mock_subscription.title = custom_name
        mock_subscription.created_at = datetime.utcnow()

        mock_repo.create_or_update_subscription.return_value = mock_subscription

        # 模拟单集创建
        mock_episode = Mock()
        mock_episode.id = 1
        mock_repo.create_or_update_episode.return_value = (mock_episode, True)

        # 模拟订阅数量检查
        mock_repo.get_user_subscriptions.return_value = []

        # 执行测试
        result_subscription, result_episodes = await podcast_service.add_subscription(
            feed_url=feed_url
        )

        # 验证结果
        assert result_subscription == mock_subscription
        assert len(result_episodes) == 5

        # 验证调用
        mock_parser.fetch_and_parse_feed.assert_called_once_with(feed_url)
        assert mock_repo.create_or_update_subscription.call_count == 1
        assert mock_repo.create_or_update_episode.call_count == 5

    @pytest.mark.asyncio
    async def test_add_subscription_invalid_feed(self, podcast_service, mock_parser):
        """测试添加无效RSS订阅"""
        feed_url = "https://example.com/invalid.rss"
        mock_parser.fetch_and_parse_feed.return_value = (False, None, "无效的RSS格式")

        with pytest.raises(ValueError, match="无法解析播客"):
            await podcast_service.add_subscription(feed_url=feed_url)

    @pytest.mark.asyncio
    async def test_add_subscription_limit_exceeded(self, podcast_service, mock_repo, mock_parser):
        """测试订阅数量超限"""
        feed_url = "https://example.com/podcast.rss"

        # 模拟RSS解析成功
        mock_feed = Mock()
        mock_parser.fetch_and_parse_feed.return_value = (True, mock_feed, None)

        # 模拟已达到订阅数量限制
        mock_repo.get_user_subscriptions.return_value = [Mock() for _ in range(100)]

        with patch('app.domains.podcast.services.settings.MAX_PODCAST_SUBSCRIPTIONS', 50):
            with pytest.raises(ValueError, match="已达到最大订阅数量"):
                await podcast_service.add_subscription(feed_url=feed_url)

    @pytest.mark.asyncio
    async def test_list_subscriptions(self, podcast_service, mock_repo):
        """测试获取订阅列表"""
        # 模拟订阅数据
        mock_subscriptions = [
            Mock(id=1, title="播客1", created_at=datetime.utcnow()),
            Mock(id=2, title="播客2", created_at=datetime.utcnow())
        ]
        mock_repo.get_user_subscriptions_paginated.return_value = (mock_subscriptions, 2)

        # 模拟单集数据
        mock_episodes = [Mock() for _ in range(3)]
        mock_repo.get_subscription_episodes.return_value = mock_episodes

        # 执行测试
        result, total = await podcast_service.list_subscriptions(page=1, size=20)

        # 验证结果
        assert total == 2
        assert len(result) == 2
        assert result[0]["id"] == 1

    @pytest.mark.asyncio
    async def test_update_playback_progress(self, podcast_service, mock_repo):
        """测试更新播放进度"""
        episode_id = 1
        position = 600
        is_playing = True

        # 模拟单集
        mock_episode = Mock()
        mock_episode.audio_duration = 1800
        mock_repo.get_episode_by_id.return_value = mock_episode

        # 模拟播放状态
        mock_playback = Mock()
        mock_playback.current_position = position
        mock_playback.is_playing = is_playing
        mock_playback.playback_rate = 1.0
        mock_playback.play_count = 2
        mock_playback.last_updated_at = datetime.utcnow()
        mock_repo.update_playback_progress.return_value = mock_playback

        # 执行测试
        result = await podcast_service.update_playback_progress(
            episode_id, position, is_playing
        )

        # 验证结果
        assert result["progress"] == position
        assert result["is_playing"] is True

    @pytest.mark.asyncio
    async def test_get_episode_with_summary(self, podcast_service, mock_repo):
        """测试获取单集详情和摘要"""
        episode_id = 1

        # 模拟单集数据
        mock_episode = Mock()
        mock_episode.id = episode_id
        mock_episode.title = "测试单集"
        mock_episode.description = "单集描述"
        mock_episode.audio_url = "https://example.com/ep.mp3"
        mock_episode.audio_duration = 1800
        mock_episode.published_at = datetime.utcnow()
        mock_episode.ai_summary = None
        mock_episode.status = "pending_summary"
        mock_episode.play_count = 0
        mock_repo.get_episode_by_id.return_value = mock_episode

        # 模拟播放状态
        mock_playback = Mock()
        mock_playback.current_position = 600
        mock_playback.is_playing = False
        mock_playback.playback_rate = 1.0
        mock_repo.get_playback_state.return_value = mock_playback

        # 执行测试
        result = await podcast_service.get_episode_with_summary(episode_id)

        # 验证结果
        assert result["id"] == episode_id
        assert result["title"] == "测试单集"
        assert result["playback"]["progress"] == 600
        assert result["playback"]["is_playing"] is False

    @pytest.mark.asyncio
    async def test_generate_summary_for_episode(self, podcast_service, mock_repo):
        """测试为单集生成AI摘要"""
        episode_id = 1

        # 模拟单集
        mock_episode = Mock()
        mock_episode.id = episode_id
        mock_episode.title = "测试单集"
        mock_episode.description = "单集描述内容"
        mock_episode.ai_summary = None
        mock_repo.get_episode_by_id.return_value = mock_episode

        # 模拟生成摘要的结果
        summary_text = "这是AI生成的摘要"
        with patch.object(podcast_service, '_generate_summary', return_value=summary_text):
            result = await podcast_service.generate_summary_for_episode(episode_id)

        assert result == summary_text

    @pytest.mark.asyncio
    async def test_search_podcasts(self, podcast_service, mock_repo):
        """测试搜索播客"""
        query = "测试关键词"
        search_in = "all"

        # 模拟搜索结果
        mock_episodes = [
            Mock(id=1, title="包含关键词的单集", description="描述"),
            Mock(id=2, title="另一个单集", description="包含关键词的描述")
        ]
        mock_repo.search_episodes.return_value = (mock_episodes, 2)

        # 执行测试
        result, total = await podcast_service.search_podcasts(
            query=query, search_in=search_in, page=1, size=20
        )

        # 验证结果
        assert total == 2
        assert len(result) == 2
        assert "关键词" in result[0]["title"]

    @pytest.mark.asyncio
    async def test_get_user_stats(self, podcast_service, mock_repo):
        """测试获取用户统计"""
        # 模拟订阅
        mock_subscriptions = [Mock(status="active") for _ in range(3)]
        mock_repo.get_user_subscriptions.return_value = mock_subscriptions

        # 模拟单集
        mock_episodes = [Mock() for _ in range(10)]
        for ep in mock_episodes:
            ep.ai_summary = True if ep.id % 2 == 0 else False
        mock_repo.get_subscription_episodes.return_value = mock_episodes

        # 模拟播放状态
        mock_playback = Mock()
        mock_playback.current_position = 600
        mock_repo.get_playback_state.return_value = mock_playback

        # 模拟最近播放
        mock_repo.get_recently_played.return_value = []

        # 模拟播放日期
        mock_repo.get_recent_play_dates.return_value = {
            datetime.utcnow().date() - timedelta(days=i)
            for i in range(5)
        }

        # 执行测试
        result = await podcast_service.get_user_stats()

        # 验证结果
        assert result["total_subscriptions"] == 3
        assert result["total_episodes"] == 30  # 3 * 10
        assert result["summaries_generated"] == 15
        assert result["pending_summaries"] == 15
        assert result["listening_streak"] >= 1

    @pytest.mark.asyncio
    async def test_refresh_subscription(self, podcast_service, mock_repo, mock_parser):
        """测试刷新订阅"""
        subscription_id = 1

        # 模拟现有订阅
        mock_subscription = Mock()
        mock_subscription.id = subscription_id
        mock_subscription.source_url = "https://example.com/podcast.rss"
        mock_repo.get_subscription_by_id.return_value = mock_subscription

        # 模拟RSS解析
        mock_feed = Mock()
        mock_feed.title = "更新的播客"
        mock_feed.episodes = [Mock() for _ in range(3)]
        mock_parser.fetch_and_parse_feed.return_value = (True, mock_feed, None)

        # 模拟单集创建
        mock_episode = Mock()
        mock_repo.create_or_update_episode.return_value = (mock_episode, True)

        # 执行测试
        result = await podcast_service.refresh_subscription(subscription_id)

        # 验证结果
        assert len(result) == 3
        mock_repo.update_subscription_fetch_time.assert_called_once_with(subscription_id)

    @pytest.mark.asyncio
    async def test_get_recommendations(self, podcast_service, mock_repo):
        """测试获取推荐"""
        # 模拟喜欢的单集
        mock_episodes = [
            Mock(
                id=1,
                title="推荐单集1",
                description="描述1",
                subscription=Mock(title="播客1")
            ),
            Mock(
                id=2,
                title="推荐单集2",
                description="描述2",
                subscription=Mock(title="播客2")
            )
        ]
        mock_repo.get_liked_episodes.return_value = mock_episodes

        # 执行测试
        result = await podcast_service.get_recommendations(limit=2)

        # 验证结果
        assert len(result) == 2
        assert result[0]["title"] == "推荐单集1"
        assert result[0]["recommendation_reason"] == "基于您收听历史推荐"
        assert result[0]["match_score"] == 0.85

    @pytest.mark.asyncio
    async def test_generate_summary_with_transcript(self, podcast_service, mock_repo):
        """测试使用转录文本生成摘要"""
        episode_id = 1
        use_transcript = True

        # 模拟单集（有转录文本）
        mock_episode = Mock()
        mock_episode.id = episode_id
        mock_episode.transcript_content = "这是转录文本内容，比较长..."
        mock_episode.description = "简短描述"
        mock_repo.get_episode_by_id.return_value = mock_episode

        # 模拟内容净化器
        with patch.object(podcast_service.sanitizer, 'sanitize', return_value="净化后的内容"):
            # 模拟LLM调用
            mock_summary = "基于转录生成的AI摘要"
            with patch.object(podcast_service, '_call_llm_for_summary', return_value=mock_summary):
                # 模拟数据库更新
                mock_repo.update_ai_summary.return_value = None

                # 执行测试
                result = await podcast_service._generate_summary(mock_episode)

        # 验证结果
        assert result == mock_summary
        # 验证使用了转录文本而非描述
        podcast_service.sanitizer.sanitize.assert_called_once_with(
            mock_episode.transcript_content, 1, "podcast_transcript"
        )

    @pytest.mark.asyncio
    async def test_calculate_listening_streak(self, podcast_service, mock_repo):
        """测试计算连续收听天数"""
        # 模拟最近播放日期（连续5天）
        today = datetime.utcnow().date()
        recent_dates = {today - timedelta(days=i) for i in range(5)}
        mock_repo.get_recent_play_dates.return_value = recent_dates

        # 执行测试
        result = await podcast_service._calculate_listening_streak()

        # 验证结果
        assert result == 5

    @pytest.mark.asyncio
    async def test_calculate_listening_streak_no_activity(self, podcast_service, mock_repo):
        """测试没有收听记录时的连续天数"""
        mock_repo.get_recent_play_dates.return_value = set()

        # 执行测试
        result = await podcast_service._calculate_listening_streak()

        # 验证结果
        assert result == 0

    @pytest.mark.asyncio
    async def test_rule_based_summary(self, podcast_service):
        """测试规则生成摘要（无LLM时）"""
        title = "测试播客单集"
        content = "这是一个关于技术的播客，主要内容是讨论最新的AI发展趋势。"

        # 执行测试
        result = podcast_service._rule_based_summary(title, content)

        # 验证结果
        assert title in result
        assert "技术" in result or "AI" in result
        assert "此为快速总结" in result