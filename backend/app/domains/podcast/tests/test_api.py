"""
播客API测试用例
"""

from datetime import datetime
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


class TestPodcastSubscriptionAPI:
    """播客订阅API测试"""

    @pytest.fixture
    def mock_user(self):
        """模拟认证用户"""
        return {"sub": 1, "username": "testuser"}

    @pytest.fixture
    def mock_podcast_service(self):
        """模拟播客服务"""
        with patch('app.domains.podcast.api.routes.PodcastService') as mock:
            service_instance = AsyncMock()
            mock.return_value = service_instance
            yield service_instance

    def test_create_subscription_success(self, mock_user, mock_podcast_service):
        """测试成功创建播客订阅"""
        # 准备测试数据
        subscription_data = {
            "feed_url": "https://example.com/podcast.rss",
            "custom_name": "测试播客",
            "category_ids": [1, 2]
        }

        # 模拟返回值
        mock_subscription = Mock()
        mock_subscription.id = 1
        mock_subscription.user_id = 1
        mock_subscription.title = "测试播客"
        mock_subscription.description = "这是一个测试播客"
        mock_subscription.source_url = "https://example.com/podcast.rss"
        mock_subscription.status = "active"
        mock_subscription.last_fetched_at = None
        mock_subscription.error_message = None
        mock_subscription.fetch_interval = 3600
        mock_subscription.created_at = datetime.utcnow()
        mock_subscription.updated_at = None

        mock_podcast_service.add_subscription.return_value = (
            mock_subscription, []
        )

        # 发送请求
        response = client.post(
            "/api/v1/podcasts/subscriptions",
            json=subscription_data,
            headers={"Authorization": "Bearer test_token"}
        )

        # 验证响应
        assert response.status_code == 201
        data = response.json()
        assert data["id"] == 1
        assert data["title"] == "测试播客"
        assert data["source_url"] == "https://example.com/podcast.rss"

        # 验证服务调用
        mock_podcast_service.add_subscription.assert_called_once_with(
            feed_url="https://example.com/podcast.rss",
            custom_name="测试播客",
            category_ids=[1, 2]
        )

    def test_create_subscription_invalid_url(self, mock_user):
        """测试无效URL创建订阅"""
        subscription_data = {
            "feed_url": "invalid-url",
            "custom_name": "测试播客"
        }

        response = client.post(
            "/api/v1/podcasts/subscriptions",
            json=subscription_data,
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 422  # Validation error

    def test_list_subscriptions(self, mock_user, mock_podcast_service):
        """测试获取订阅列表"""
        # 模拟返回数据
        mock_subscriptions = [
            {
                "id": 1,
                "title": "播客1",
                "description": "描述1",
                "episode_count": 10,
                "unplayed_count": 5
            },
            {
                "id": 2,
                "title": "播客2",
                "description": "描述2",
                "episode_count": 20,
                "unplayed_count": 10
            }
        ]

        mock_podcast_service.list_subscriptions.return_value = (
            mock_subscriptions, 2
        )

        response = client.get(
            "/api/v1/podcasts/subscriptions",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["subscriptions"]) == 2
        assert data["subscriptions"][0]["title"] == "播客1"

    def test_get_subscription_detail(self, mock_user, mock_podcast_service):
        """测试获取订阅详情"""
        mock_subscription_detail = {
            "id": 1,
            "title": "测试播客",
            "description": "详细描述",
            "episode_count": 50,
            "episodes": []
        }

        mock_podcast_service.get_subscription_details.return_value = mock_subscription_detail

        response = client.get(
            "/api/v1/podcasts/subscriptions/1",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 1
        assert data["title"] == "测试播客"

    def test_delete_subscription(self, mock_user, mock_podcast_service):
        """测试删除订阅"""
        mock_podcast_service.remove_subscription.return_value = True

        response = client.delete(
            "/api/v1/podcasts/subscriptions/1",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "订阅已删除" in data["message"]


class TestPodcastEpisodeAPI:
    """播客单集API测试"""

    @pytest.fixture
    def mock_user(self):
        return {"sub": 1, "username": "testuser"}

    @pytest.fixture
    def mock_podcast_service(self):
        with patch('app.domains.podcast.api.routes.PodcastService') as mock:
            service_instance = AsyncMock()
            mock.return_value = service_instance
            yield service_instance

    def test_list_episodes(self, mock_user, mock_podcast_service):
        """测试获取单集列表"""
        mock_episodes = [
            {
                "id": 1,
                "title": "单集1",
                "description": "描述1",
                "audio_url": "https://example.com/ep1.mp3",
                "duration": 1800,
                "is_played": False
            },
            {
                "id": 2,
                "title": "单集2",
                "description": "描述2",
                "audio_url": "https://example.com/ep2.mp3",
                "duration": 2400,
                "is_played": True
            }
        ]

        mock_podcast_service.list_episodes.return_value = (mock_episodes, 2)

        response = client.get(
            "/api/v1/podcasts/episodes",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 2
        assert len(data["episodes"]) == 2
        assert data["episodes"][0]["title"] == "单集1"

    def test_get_episode_detail(self, mock_user, mock_podcast_service):
        """测试获取单集详情"""
        mock_episode = {
            "id": 1,
            "title": "测试单集",
            "description": "单集描述",
            "audio_url": "https://example.com/ep1.mp3",
            "ai_summary": "这是AI生成的摘要",
            "transcript": "这是转录文本",
            "playback": {
                "progress": 600,
                "is_playing": True
            }
        }

        mock_podcast_service.get_episode_with_summary.return_value = mock_episode

        response = client.get(
            "/api/v1/podcasts/episodes/1",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == 1
        assert data["title"] == "测试单集"
        assert data["ai_summary"] == "这是AI生成的摘要"

    def test_update_playback_progress(self, mock_user, mock_podcast_service):
        """测试更新播放进度"""
        playback_data = {
            "position": 900,
            "is_playing": True,
            "playback_rate": 1.5
        }

        mock_result = {
            "progress": 900,
            "is_playing": True,
            "playback_rate": 1.5,
            "play_count": 2,
            "last_updated_at": datetime.utcnow(),
            "progress_percentage": 50.0,
            "remaining_time": 900
        }

        mock_podcast_service.update_playback_progress.return_value = mock_result

        response = client.put(
            "/api/v1/podcasts/episodes/1/playback",
            json=playback_data,
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["episode_id"] == 1
        assert data["current_position"] == 900
        assert data["is_playing"] is True

    def test_generate_summary(self, mock_user, mock_podcast_service):
        """测试生成AI摘要"""
        request_data = {
            "force_regenerate": False,
            "use_transcript": True
        }

        mock_summary = {
            "content": "这是生成的AI摘要内容",
            "version": "v1",
            "confidence_score": 0.85,
            "transcript_used": True,
            "generated_at": datetime.utcnow()
        }

        mock_podcast_service.generate_summary_for_episode.return_value = mock_summary

        response = client.post(
            "/api/v1/podcasts/episodes/1/summary",
            json=request_data,
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["episode_id"] == 1
        assert data["summary"] == "这是生成的AI摘要内容"
        assert data["transcript_used"] is True

    def test_search_podcasts(self, mock_user, mock_podcast_service):
        """测试搜索播客"""
        mock_episodes = [
            {
                "id": 1,
                "title": "搜索结果1",
                "description": "包含关键词的描述",
                "relevance_score": 0.95
            }
        ]

        mock_podcast_service.search_podcasts.return_value = (mock_episodes, 1)

        response = client.get(
            "/api/v1/podcasts/search?q=关键词",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert len(data["episodes"]) == 1
        assert "关键词" in data["episodes"][0]["title"]

    def test_get_podcast_stats(self, mock_user, mock_podcast_service):
        """测试获取播客统计"""
        mock_stats = {
            "total_subscriptions": 5,
            "total_episodes": 100,
            "total_playtime": 36000,
            "summaries_generated": 80,
            "pending_summaries": 20,
            "listening_streak": 7
        }

        mock_podcast_service.get_user_stats.return_value = mock_stats

        response = client.get(
            "/api/v1/podcasts/stats",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["total_subscriptions"] == 5
        assert data["total_episodes"] == 100
        assert data["listening_streak"] == 7


class TestPodcastTaskAPI:
    """播客任务API测试"""

    @pytest.fixture
    def mock_user(self):
        return {"sub": 1, "username": "testuser"}

    @pytest.fixture
    def mock_podcast_service(self):
        with patch('app.domains.podcast.api.routes.PodcastService') as mock:
            service_instance = AsyncMock()
            mock.return_value = service_instance
            yield service_instance

    def test_refresh_subscription(self, mock_user, mock_podcast_service):
        """测试刷新订阅"""
        mock_episodes = [Mock(), Mock(), Mock()]  # 3个新单集
        mock_podcast_service.refresh_subscription.return_value = mock_episodes

        response = client.post(
            "/api/v1/podcasts/subscriptions/1/refresh",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["new_episodes"] == 3
        assert "发现 3 期新节目" in data["message"]

    def test_get_pending_summaries(self, mock_user, mock_podcast_service):
        """测试获取待总结列表"""
        mock_pending = [
            {
                "episode_id": 1,
                "subscription_title": "播客1",
                "episode_title": "单集1",
                "size_estimate": 5000
            }
        ]

        mock_podcast_service.get_pending_summaries.return_value = mock_pending

        response = client.get(
            "/api/v1/podcasts/summaries/pending",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 1
        assert len(data["episodes"]) == 1
        assert data["episodes"][0]["episode_title"] == "单集1"

    def test_get_recommendations(self, mock_user, mock_podcast_service):
        """测试获取推荐"""
        mock_recommendations = [
            {
                "episode_id": 1,
                "title": "推荐单集",
                "subscription_title": "推荐播客",
                "recommendation_reason": "基于收听历史",
                "match_score": 0.9
            }
        ]

        mock_podcast_service.get_recommendations.return_value = mock_recommendations

        response = client.get(
            "/api/v1/podcasts/recommendations",
            headers={"Authorization": "Bearer test_token"}
        )

        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["title"] == "推荐单集"
        assert data[0]["match_score"] == 0.9


# === 集成测试 ===

@pytest.mark.asyncio
class TestPodcastIntegration:
    """播客功能集成测试"""

    async def test_podcast_workflow(self):
        """测试完整的播客工作流程"""
        # TODO: 实现端到端测试
        # 1. 添加订阅
        # 2. 获取单集列表
        # 3. 播放单集
        # 4. 生成摘要
        # 5. 搜索功能
        pass