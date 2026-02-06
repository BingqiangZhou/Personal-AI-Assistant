"""
播客功能全面端到端测试
使用真实的RSS feed进行测试

测试覆盖：
1. RSS订阅添加和解析
2. 单集获取和AI摘要
3. 播放进度跟踪
4. 错误处理和边界情况
5. 性能测试
"""

import asyncio
import time

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


try:
    from app.core.database import get_db_session, test_engine
    from app.core.security import create_access_token
    from app.core.test_database import TestSessionLocal, get_test_db
    from app.domains.user.models import User
    from app.main import app
except Exception as exc:  # pragma: no cover - legacy env guard
    pytest.skip(
        f"Legacy comprehensive podcast test requires test DB helpers: {exc}",
        allow_module_level=True,
    )


# 测试配置
TEST_RSS_URL = "https://feed.xyzfm.space/mcklbwxjdvfu"
TEST_RSS_INVALID_URL = "https://invalid-url-that-does-not-exist.com/rss.xml"
TEST_USER_EMAIL = "testuser@podcast.com"
TEST_USER_PASSWORD = "testpass123"

# 测试数据库设置
app.dependency_overrides[get_db_session] = get_test_db


@pytest.fixture(scope="session")
def event_loop():
    """创建事件循环"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def client():
    """创建测试客户端"""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
async def db_session():
    """创建测试数据库会话"""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with TestSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """创建测试用户"""
    from app.core.security import get_password_hash

    user = User(
        email=TEST_USER_EMAIL,
        username="testuser",
        hashed_password=get_password_hash(TEST_USER_PASSWORD),
        is_active=True,
        is_verified=True
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def auth_headers(test_user: User) -> dict[str, str]:
    """生成认证头"""
    token = create_access_token(data={"sub": str(test_user.id)})
    return {"Authorization": f"Bearer {token}"}


class TestPodcastSubscriptionWorkflow:
    """播客订阅工作流测试"""

    async def test_01_add_rss_subscription_success(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试成功添加RSS订阅"""
        subscription_data = {
            "feed_url": TEST_RSS_URL,
            "custom_name": "测试播客订阅",
            "category_ids": [1]
        }

        response = await client.post(
            "/api/v1/subscriptions/podcasts",
            json=subscription_data,
            headers=auth_headers
        )

        assert response.status_code == 201
        data = response.json()
        assert data["title"] is not None
        assert data["source_url"] == TEST_RSS_URL
        assert data["status"] == "active"
        assert data["episode_count"] > 0

        # 保存订阅ID供后续测试使用
        TestPodcastSubscriptionWorkflow.subscription_id = data["id"]
        print(f"✓ 成功创建订阅 ID: {data['id']}, 获取到 {data['episode_count']} 个单集")

    async def test_02_list_subscriptions(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试获取订阅列表"""
        response = await client.get(
            "/api/v1/subscriptions/podcasts",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "subscriptions" in data
        assert len(data["subscriptions"]) >= 1
        assert data["total"] >= 1

        # 验证订阅详情
        subscription = data["subscriptions"][0]
        assert subscription["id"] == TestPodcastSubscriptionWorkflow.subscription_id
        assert subscription["title"] == "测试播客订阅"

    async def test_03_get_subscription_details(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试获取订阅详情"""
        response = await client.get(
            f"/api/v1/subscriptions/podcasts/{TestPodcastSubscriptionWorkflow.subscription_id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == TestPodcastSubscriptionWorkflow.subscription_id
        assert data["title"] is not None
        assert data["description"] is not None
        assert data["episode_count"] > 0

    async def test_04_get_episodes_list(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试获取单集列表"""
        response = await client.get(
            f"/api/v1/podcasts/episodes?subscription_id={TestPodcastSubscriptionWorkflow.subscription_id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "episodes" in data
        assert len(data["episodes"]) > 0

        # 保存第一个单集ID供后续测试
        TestPodcastSubscriptionWorkflow.episode_id = data["episodes"][0]["id"]
        print(f"✓ 获取到 {len(data['episodes'])} 个单集")

    async def test_05_get_episode_detail(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试获取单集详情"""
        response = await client.get(
            f"/api/v1/podcasts/episodes/{TestPodcastSubscriptionWorkflow.episode_id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == TestPodcastSubscriptionWorkflow.episode_id
        assert data["title"] is not None
        assert data["description"] is not None
        assert data["audio_url"] is not None
        assert data["subscription_id"] == TestPodcastSubscriptionWorkflow.subscription_id

    async def test_06_update_playback_progress(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试更新播放进度"""
        playback_data = {
            "current_position": 120,  # 2分钟
            "is_playing": True,
            "playback_rate": 1.5
        }

        response = await client.post(
            f"/api/v1/podcasts/episodes/{TestPodcastSubscriptionWorkflow.episode_id}/progress",
            json=playback_data,
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["current_position"] == 120
        assert data["is_playing"] is True
        assert data["playback_rate"] == 1.5
        assert data["play_count"] >= 1

        print(f"✓ 更新播放进度到 {data['current_position']} 秒")

    async def test_07_get_playback_state(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试获取播放状态"""
        response = await client.get(
            f"/api/v1/podcasts/episodes/{TestPodcastSubscriptionWorkflow.episode_id}/progress",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["current_position"] == 120
        assert data["is_playing"] is True

    async def test_08_request_ai_summary(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试请求AI摘要"""
        summary_request = {
            "force_regenerate": False,
            "language": "zh"
        }

        response = await client.post(
            f"/api/v1/podcasts/episodes/{TestPodcastSubscriptionWorkflow.episode_id}/summary",
            json=summary_request,
            headers=auth_headers
        )

        # 可能返回202表示正在处理
        assert response.status_code in [200, 202]

        if response.status_code == 200:
            data = response.json()
            assert data["episode_id"] == TestPodcastSubscriptionWorkflow.episode_id
            if data.get("ai_summary"):
                print("✓ AI摘要生成成功")
            else:
                print("ℹ AI摘要处理中...")

    async def test_09_search_episodes(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试搜索单集"""
        search_params = {
            "query": "播客",
            "subscription_id": TestPodcastSubscriptionWorkflow.subscription_id
        }

        response = await client.get(
            "/api/v1/podcasts/episodes/search",
            params=search_params,
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "episodes" in data
        print(f"✓ 搜索到 {len(data['episodes'])} 个匹配单集")

    async def test_10_get_podcast_stats(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试获取播客统计信息"""
        response = await client.get(
            "/api/v1/podcasts/stats",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "total_subscriptions" in data
        assert "total_episodes" in data
        assert "total_playback_time" in data
        assert data["total_subscriptions"] >= 1

        print(f"✓ 播客统计: {data['total_subscriptions']} 个订阅, {data['total_episodes']} 个单集")


class TestPodcastErrorHandling:
    """播客功能错误处理测试"""

    async def test_invalid_rss_url(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试无效RSS URL"""
        subscription_data = {
            "feed_url": TEST_RSS_INVALID_URL,
            "custom_name": "无效播客"
        }

        response = await client.post(
            "/api/v1/subscriptions/podcasts",
            json=subscription_data,
            headers=auth_headers
        )

        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        print(f"✓ 正确处理无效RSS URL: {data['detail']}")

    async def test_duplicate_subscription(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试重复订阅"""
        # 先添加一个订阅
        subscription_data = {
            "feed_url": TEST_RSS_URL,
            "custom_name": "重复测试播客"
        }

        await client.post(
            "/api/v1/subscriptions/podcasts",
            json=subscription_data,
            headers=auth_headers
        )

        # 尝试再次添加相同的订阅
        response = await client.post(
            "/api/v1/subscriptions/podcasts",
            json=subscription_data,
            headers=auth_headers
        )

        # 应该返回409 Conflict或400 Bad Request
        assert response.status_code in [409, 400]
        print("✓ 正确处理重复订阅")

    async def test_unauthorized_access(self, client: AsyncClient):
        """测试未授权访问"""
        response = await client.get("/api/v1/subscriptions/podcasts")
        assert response.status_code == 401

        response = await client.post(
            "/api/v1/subscriptions/podcasts",
            json={"feed_url": TEST_RSS_URL}
        )
        assert response.status_code == 401

        print("✓ 正确处理未授权访问")

    async def test_nonexistent_episode(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试不存在的单集ID"""
        fake_id = 99999

        response = await client.get(
            f"/api/v1/podcasts/episodes/{fake_id}",
            headers=auth_headers
        )
        assert response.status_code == 404

        response = await client.post(
            f"/api/v1/podcasts/episodes/{fake_id}/progress",
            json={"current_position": 10},
            headers=auth_headers
        )
        assert response.status_code == 404

        print("✓ 正确处理不存在的单集ID")

    async def test_invalid_playback_data(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试无效的播放数据"""
        # 需要先获取一个有效的episode_id
        response = await client.get(
            "/api/v1/podcasts/episodes",
            headers=auth_headers
        )

        if response.status_code == 200:
            episodes = response.json().get("episodes", [])
            if episodes:
                episode_id = episodes[0]["id"]

                # 发送无效数据
                invalid_data = {
                    "current_position": -10,  # 负数
                    "playback_rate": 0        # 无效播放速度
                }

                response = await client.post(
                    f"/api/v1/podcasts/episodes/{episode_id}/progress",
                    json=invalid_data,
                    headers=auth_headers
                )

                # 应该返回422验证错误
                assert response.status_code == 422
                print("✓ 正确处理无效播放数据")

    async def test_malformed_xml_feed(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试格式错误的XML feed"""
        malformed_url = "data:text/xml,<invalid>xml</invalid>"

        subscription_data = {
            "feed_url": malformed_url,
            "custom_name": "格式错误播客"
        }

        response = await client.post(
            "/api/v1/subscriptions/podcasts",
            json=subscription_data,
            headers=auth_headers
        )

        # 应该处理错误
        assert response.status_code in [400, 500]
        print("✓ 正确处理格式错误的XML feed")


class TestPodcastPerformance:
    """播客功能性能测试"""

    async def test_subscription_parsing_performance(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试RSS解析性能"""
        subscription_data = {
            "feed_url": TEST_RSS_URL,
            "custom_name": "性能测试播客"
        }

        start_time = time.time()
        response = await client.post(
            "/api/v1/subscriptions/podcasts",
            json=subscription_data,
            headers=auth_headers
        )
        end_time = time.time()

        assert response.status_code == 201
        parsing_time = end_time - start_time

        # RSS解析应该在10秒内完成
        assert parsing_time < 10.0
        print(f"✓ RSS解析耗时: {parsing_time:.2f} 秒")

    async def test_episodes_list_performance(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试单集列表查询性能"""
        # 先获取订阅列表
        response = await client.get(
            "/api/v1/subscriptions/podcasts",
            headers=auth_headers
        )

        if response.status_code == 200:
            subscriptions = response.json().get("subscriptions", [])
            if subscriptions:
                subscription_id = subscriptions[0]["id"]

                start_time = time.time()
                response = await client.get(
                    f"/api/v1/podcasts/episodes?subscription_id={subscription_id}&limit=50",
                    headers=auth_headers
                )
                end_time = time.time()

                assert response.status_code == 200
                query_time = end_time - start_time

                # 查询应该在1秒内完成
                assert query_time < 1.0
                print(f"✓ 单集列表查询耗时: {query_time:.3f} 秒")

    async def test_concurrent_requests(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试并发请求处理"""
        # 创建多个并发请求
        tasks = []
        for i in range(10):
            task = client.get(
                "/api/v1/subscriptions/podcasts",
                headers=auth_headers
            )
            tasks.append(task)

        start_time = time.time()
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()

        # 验证所有请求都成功
        success_count = sum(1 for r in responses if getattr(r, 'status_code', None) == 200)
        assert success_count >= 8  # 至少80%的成功率

        total_time = end_time - start_time
        avg_time = total_time / 10

        # 平均响应时间应该合理
        assert avg_time < 2.0
        print(f"✓ 10个并发请求平均耗时: {avg_time:.3f} 秒")


class TestPodcastDataIntegrity:
    """播客数据完整性测试"""

    async def test_episode_metadata_integrity(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试单集元数据完整性"""
        # 获取单集详情
        response = await client.get(
            "/api/v1/podcasts/episodes",
            headers=auth_headers
        )

        if response.status_code == 200:
            episodes = response.json().get("episodes", [])
            if episodes:
                episode_id = episodes[0]["id"]

                response = await client.get(
                    f"/api/v1/podcasts/episodes/{episode_id}",
                    headers=auth_headers
                )

                assert response.status_code == 200
                episode = response.json()

                # 验证必要字段存在
                required_fields = ["id", "title", "description", "audio_url", "published_at"]
                for field in required_fields:
                    assert field in episode
                    assert episode[field] is not None

                # 验证URL格式
                assert episode["audio_url"].startswith(("http://", "https://"))

                print("✓ 单集元数据完整性验证通过")

    async def test_playback_progress_persistence(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试播放进度持久化"""
        # 获取单集ID
        response = await client.get(
            "/api/v1/podcasts/episodes",
            headers=auth_headers
        )

        if response.status_code == 200:
            episodes = response.json().get("episodes", [])
            if episodes:
                episode_id = episodes[0]["id"]

                # 更新播放进度
                progress_data = {
                    "current_position": 300,
                    "is_playing": False
                }

                response = await client.post(
                    f"/api/v1/podcasts/episodes/{episode_id}/progress",
                    json=progress_data,
                    headers=auth_headers
                )

                assert response.status_code == 200

                # 稍等片刻确保数据已保存
                await asyncio.sleep(0.1)

                # 再次获取播放状态
                response = await client.get(
                    f"/api/v1/podcasts/episodes/{episode_id}/progress",
                    headers=auth_headers
                )

                assert response.status_code == 200
                state = response.json()
                assert state["current_position"] == 300
                assert state["is_playing"] is False

                print("✓ 播放进度持久化验证通过")


# 运行所有测试的主函数
async def run_all_tests():
    """运行所有测试套件"""
    test_classes = [
        TestPodcastSubscriptionWorkflow,
        TestPodcastErrorHandling,
        TestPodcastPerformance,
        TestPodcastDataIntegrity
    ]

    total_tests = 0
    passed_tests = 0
    failed_tests = []

    for test_class in test_classes:
        print(f"\n{'='*60}")
        print(f"运行测试类: {test_class.__name__}")
        print(f"{'='*60}")

        # 创建测试实例
        instance = test_class()

        # 获取所有测试方法
        test_methods = [method for method in dir(instance) if method.startswith("test_")]

        for method_name in test_methods:
            total_tests += 1
            try:
                # 获取测试方法
                test_method = getattr(instance, method_name)

                # 准备测试客户端和认证
                async with AsyncClient(app=app, base_url="http://test") as client:
                    # 创建测试用户和获取认证头
                    from app.core.security import create_access_token, get_password_hash
                    from app.core.test_database import TestSessionLocal
                    from app.domains.user.models import User

                    async with TestSessionLocal() as session:
                        # 创建测试用户
                        user = User(
                            email=TEST_USER_EMAIL,
                            username="testuser",
                            hashed_password=get_password_hash(TEST_USER_PASSWORD),
                            is_active=True,
                            is_verified=True
                        )
                        session.add(user)
                        await session.commit()
                        await session.refresh(user)

                        # 生成认证头
                        token = create_access_token(data={"sub": str(user.id)})
                        auth_headers = {"Authorization": f"Bearer {token}"}

                        # 执行测试
                        await test_method(client, auth_headers)

                print(f"✓ {method_name} - PASSED")
                passed_tests += 1

            except Exception as e:
                print(f"✗ {method_name} - FAILED: {str(e)}")
                failed_tests.append((method_name, str(e)))

    # 打印测试报告
    print(f"\n{'='*60}")
    print("测试执行完成")
    print(f"{'='*60}")
    print(f"总测试数: {total_tests}")
    print(f"通过: {passed_tests}")
    print(f"失败: {len(failed_tests)}")
    print(f"成功率: {(passed_tests/total_tests*100):.1f}%")

    if failed_tests:
        print("\n失败的测试:")
        for test_name, error in failed_tests:
            print(f"  - {test_name}: {error}")

    return passed_tests, total_tests - passed_tests


if __name__ == "__main__":
    # 运行所有测试
    passed, failed = asyncio.run(run_all_tests())

    # 设置退出码
    import sys
    sys.exit(0 if failed == 0 else 1)
