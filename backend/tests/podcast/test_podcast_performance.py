"""
播客功能性能测试
包括负载测试、压力测试和响应时间分析
"""

import asyncio
import statistics
import threading
import time
from datetime import datetime

import psutil
import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.security import create_access_token
from app.core.test_database import TestSessionLocal
from app.domains.podcast.models import PodcastEpisode
from app.domains.user.models import User
from app.main import app


class PerformanceMonitor:
    """性能监控器"""

    def __init__(self):
        self.cpu_samples = []
        self.memory_samples = []
        self.response_times = []
        self.monitoring = False
        self.monitor_thread = None

    def start_monitoring(self):
        """开始监控"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.start()

    def stop_monitoring(self):
        """停止监控"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()

    def _monitor_loop(self):
        """监控循环"""
        while self.monitoring:
            self.cpu_samples.append(psutil.cpu_percent())
            self.memory_samples.append(psutil.virtual_memory().percent)
            time.sleep(0.1)

    def record_response_time(self, duration: float):
        """记录响应时间"""
        self.response_times.append(duration)

    def get_stats(self) -> dict:
        """获取统计信息"""
        return {
            "cpu_avg": statistics.mean(self.cpu_samples) if self.cpu_samples else 0,
            "cpu_max": max(self.cpu_samples) if self.cpu_samples else 0,
            "memory_avg": statistics.mean(self.memory_samples) if self.memory_samples else 0,
            "memory_max": max(self.memory_samples) if self.memory_samples else 0,
            "response_avg": statistics.mean(self.response_times) if self.response_times else 0,
            "response_p95": statistics.quantiles(self.response_times, n=20)[18] if len(self.response_times) >= 20 else max(self.response_times),
            "response_max": max(self.response_times) if self.response_times else 0,
            "total_requests": len(self.response_times)
        }


@pytest.fixture
def perf_monitor():
    """性能监控器fixture"""
    monitor = PerformanceMonitor()
    yield monitor
    monitor.stop_monitoring()


class TestPodcastAPIPerformance:
    """播客API性能测试"""

    @pytest.fixture
    async def auth_headers(self):
        """生成认证头"""
        async with TestSessionLocal() as session:
            user = User(
                email="perf@test.com",
                username="perfuser",
                hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewaPoNHWgKpiAwJ.",
                is_active=True,
                is_verified=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            token = create_access_token(data={"sub": str(user.id)})
            return {"Authorization": f"Bearer {token}"}

    async def test_subscription_creation_performance(self, client: AsyncClient, auth_headers: dict[str, str], perf_monitor: PerformanceMonitor):
        """测试订阅创建性能"""
        TEST_RSS = "https://feed.xyzfm.space/mcklbwxjdvfu"

        perf_monitor.start_monitoring()

        # 测试连续创建订阅的响应时间
        response_times = []
        for i in range(10):
            subscription_data = {
                "feed_url": f"{TEST_RSS}?t={int(time.time())}",
                "custom_name": f"性能测试播客 {i}"
            }

            start_time = time.time()
            response = await client.post(
                "/api/v1/podcasts/subscriptions",
                json=subscription_data,
                headers=auth_headers
            )
            end_time = time.time()

            assert response.status_code in [201, 400]  # 400可能因为重复订阅
            duration = end_time - start_time
            response_times.append(duration)
            perf_monitor.record_response_time(duration)

        perf_monitor.stop_monitoring()

        # 性能断言
        avg_time = statistics.mean(response_times)
        p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)

        assert avg_time < 5.0, f"平均响应时间过长: {avg_time:.2f}s"
        assert p95_time < 10.0, f"P95响应时间过长: {p95_time:.2f}s"

        stats = perf_monitor.get_stats()
        print("✓ 订阅创建性能:")
        print(f"  - 平均响应时间: {avg_time:.3f}s")
        print(f"  - P95响应时间: {p95_time:.3f}s")
        print(f"  - CPU平均使用率: {stats['cpu_avg']:.1f}%")
        print(f"  - 内存平均使用率: {stats['memory_avg']:.1f}%")

    async def test_episodes_query_performance(self, client: AsyncClient, auth_headers: dict[str, str], perf_monitor: PerformanceMonitor):
        """测试单集查询性能"""
        # 先创建一些测试数据
        subscription_ids = []
        for i in range(5):
            subscription_data = {
                "feed_url": f"https://feed.xyzfm.space/mcklbwxjdvfu?t={i}",
                "custom_name": f"测试播客 {i}"
            }
            response = await client.post(
                "/api/v1/podcasts/subscriptions",
                json=subscription_data,
                headers=auth_headers
            )
            if response.status_code == 201:
                subscription_ids.append(response.json()["id"])

        # 测试不同查询参数的性能
        test_scenarios = [
            {"limit": 10, "description": "小批量查询"},
            {"limit": 50, "description": "中等批量查询"},
            {"limit": 100, "description": "大批量查询"},
            {"subscription_id": subscription_ids[0] if subscription_ids else None, "limit": 20, "description": "按订阅筛选"},
        ]

        perf_monitor.start_monitoring()

        for scenario in test_scenarios:
            params = {k: v for k, v in scenario.items() if k != "description"}
            response_times = []

            # 执行多次查询
            for _ in range(20):
                start_time = time.time()
                response = await client.get(
                    "/api/v1/podcasts/episodes",
                    params=params,
                    headers=auth_headers
                )
                end_time = time.time()

                assert response.status_code == 200
                duration = end_time - start_time
                response_times.append(duration)
                perf_monitor.record_response_time(duration)

            # 分析性能
            avg_time = statistics.mean(response_times)
            p95_time = statistics.quantiles(response_times, n=20)[18] if len(response_times) >= 20 else max(response_times)

            print(f"\n✓ {scenario['description']}:")
            print(f"  - 平均响应时间: {avg_time:.3f}s")
            print(f"  - P95响应时间: {p95_time:.3f}s")

            # 性能断言
            assert avg_time < 0.5, f"平均响应时间过长: {avg_time:.2f}s"

        perf_monitor.stop_monitoring()

    async def test_concurrent_subscription_creation(self, client: AsyncClient, auth_headers: dict[str, str], perf_monitor: PerformanceMonitor):
        """测试并发订阅创建"""
        concurrent_users = 20
        requests_per_user = 5

        perf_monitor.start_monitoring()

        async def create_subscriptions(user_id: int) -> tuple[float, int]:
            """为单个用户创建订阅"""
            success_count = 0
            start_time = time.time()

            tasks = []
            for i in range(requests_per_user):
                subscription_data = {
                    "feed_url": f"https://feed.xyzfm.space/mcklbwxjdvfu?user={user_id}&req={i}",
                    "custom_name": f"并发测试播客 U{user_id}R{i}"
                }
                task = client.post(
                    "/api/v1/podcasts/subscriptions",
                    json=subscription_data,
                    headers=auth_headers
                )
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            for response in responses:
                if hasattr(response, 'status_code') and response.status_code in [201, 400]:
                    success_count += 1
                    perf_monitor.record_response_time(time.time() - start_time)

            end_time = time.time()
            return end_time - start_time, success_count

        # 创建多个并发用户
        tasks = []
        for user_id in range(concurrent_users):
            task = create_subscriptions(user_id)
            tasks.append(task)

        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time

        perf_monitor.stop_monitoring()

        # 分析结果
        total_requests = concurrent_users * requests_per_user
        total_success = sum(r[1] for r in results if isinstance(r, tuple))
        throughput = total_requests / total_time if total_time > 0 else 0
        success_rate = total_success / total_requests * 100

        print("\n✓ 并发测试结果:")
        print(f"  - 并发用户数: {concurrent_users}")
        print(f"  - 每用户请求数: {requests_per_user}")
        print(f"  - 总请求数: {total_requests}")
        print(f"  - 成功请求数: {total_success}")
        print(f"  - 成功率: {success_rate:.1f}%")
        print(f"  - 总耗时: {total_time:.2f}s")
        print(f"  - 吞吐量: {throughput:.1f} 请求/秒")

        stats = perf_monitor.get_stats()
        print(f"  - CPU峰值使用率: {stats['cpu_max']:.1f}%")
        print(f"  - 内存峰值使用率: {stats['memory_max']:.1f}%")

        # 性能断言
        assert success_rate >= 90, f"成功率过低: {success_rate:.1f}%"
        assert throughput >= 10, f"吞吐量过低: {throughput:.1f} 请求/秒"

    async def test_playback_update_performance(self, client: AsyncClient, auth_headers: dict[str, str], perf_monitor: PerformanceMonitor):
        """测试播放进度更新性能"""
        # 先获取一个episode ID
        response = await client.get("/api/v1/podcasts/episodes", headers=auth_headers)
        if response.status_code != 200 or not response.json().get("episodes"):
            pytest.skip("没有可用的单集进行测试")

        episode_id = response.json()["episodes"][0]["id"]

        perf_monitor.start_monitoring()

        # 测试高频播放进度更新
        update_count = 1000
        update_times = []

        for i in range(update_count):
            playback_data = {
                "current_position": i * 10,
                "is_playing": i % 2 == 0,
                "playback_rate": 1.0 + (i % 5) * 0.25
            }

            start_time = time.time()
            response = await client.post(
                f"/api/v1/podcasts/episodes/{episode_id}/progress",
                json=playback_data,
                headers=auth_headers
            )
            end_time = time.time()

            assert response.status_code == 200
            duration = end_time - start_time
            update_times.append(duration)
            perf_monitor.record_response_time(duration)

        perf_monitor.stop_monitoring()

        # 分析性能
        avg_time = statistics.mean(update_times)
        p95_time = statistics.quantiles(update_times, n=20)[18]
        throughput = update_count / sum(update_times)

        print("\n✓ 播放进度更新性能:")
        print(f"  - 更新次数: {update_count}")
        print(f"  - 平均响应时间: {avg_time:.3f}s")
        print(f"  - P95响应时间: {p95_time:.3f}s")
        print(f"  - 吞吐量: {throughput:.1f} 更新/秒")

        # 性能断言
        assert avg_time < 0.1, f"平均响应时间过长: {avg_time:.3f}s"
        assert throughput >= 100, f"吞吐量过低: {throughput:.1f} 更新/秒"

    async def test_search_performance(self, client: AsyncClient, auth_headers: dict[str, str], perf_monitor: PerformanceMonitor):
        """测试搜索性能"""
        # 先确保有足够的测试数据
        search_terms = ["播客", "Podcast", "技术", "Technology", "AI", "人工智能"]

        perf_monitor.start_monitoring()

        search_times = []
        for term in search_terms:
            for _ in range(10):
                start_time = time.time()
                response = await client.get(
                    "/api/v1/podcasts/episodes/search",
                    params={"query": term, "limit": 20},
                    headers=auth_headers
                )
                end_time = time.time()

                assert response.status_code == 200
                duration = end_time - start_time
                search_times.append(duration)
                perf_monitor.record_response_time(duration)

        perf_monitor.stop_monitoring()

        # 分析性能
        avg_time = statistics.mean(search_times)
        p95_time = statistics.quantiles(search_times, n=20)[18] if len(search_times) >= 20 else max(search_times)

        print("\n✓ 搜索性能:")
        print(f"  - 搜索次数: {len(search_times)}")
        print(f"  - 平均响应时间: {avg_time:.3f}s")
        print(f"  - P95响应时间: {p95_time:.3f}s")

        # 性能断言
        assert avg_time < 1.0, f"平均搜索响应时间过长: {avg_time:.2f}s"

    async def test_memory_leak_detection(self, client: AsyncClient, auth_headers: dict[str, str]):
        """测试内存泄漏"""
        # 记录初始内存使用
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # 执行大量操作
        for batch in range(5):
            # 创建订阅
            for i in range(10):
                subscription_data = {
                    "feed_url": f"https://feed.xyzfm.space/mcklbwxjdvfu?batch={batch}&i={i}",
                    "custom_name": f"内存测试播客 {batch}-{i}"
                }
                await client.post(
                    "/api/v1/podcasts/subscriptions",
                    json=subscription_data,
                    headers=auth_headers
                )

            # 查询单集
            await client.get("/api/v1/podcasts/episodes", headers=auth_headers)
            await client.get("/api/v1/podcasts/subscriptions", headers=auth_headers)

            # 强制垃圾回收
            import gc
            gc.collect()

        # 记录最终内存使用
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        print("\n✓ 内存泄漏检测:")
        print(f"  - 初始内存: {initial_memory:.1f} MB")
        print(f"  - 最终内存: {final_memory:.1f} MB")
        print(f"  - 内存增长: {memory_increase:.1f} MB")

        # 内存增长应该在合理范围内（小于100MB）
        assert memory_increase < 100, f"可能存在内存泄漏，内存增长: {memory_increase:.1f} MB"


class TestPodcastDatabasePerformance:
    """数据库性能测试"""

    async def test_episode_query_optimization(self):
        """测试单集查询优化"""
        async with TestSessionLocal() as session:
            # 测试带索引的查询
            start_time = time.time()
            result = await session.execute(
                select(PodcastEpisode)
                .where(PodcastEpisode.subscription_id == 1)
                .limit(50)
            )
            episodes = result.scalars().all()
            query_time = time.time() - start_time

            print(f"✓ 带索引查询耗时: {query_time:.3f}s, 返回 {len(episodes)} 条记录")
            assert query_time < 0.01, "索引查询耗时过长"

            # 测试全表扫描
            start_time = time.time()
            result = await session.execute(
                select(PodcastEpisode)
                .where(PodcastEpisode.title.like("%测试%"))
                .limit(50)
            )
            episodes = result.scalars().all()
            scan_time = time.time() - start_time

            print(f"✓ 全表扫描耗时: {scan_time:.3f}s, 返回 {len(episodes)} 条记录")

    async def test_concurrent_db_operations(self):
        """测试并发数据库操作"""
        async def db_operation(operation_id: int):
            """单个数据库操作"""
            async with TestSessionLocal() as session:
                # 插入测试数据
                episode = PodcastEpisode(
                    subscription_id=1,
                    guid=f"test-{operation_id}",
                    title=f"测试单集 {operation_id}",
                    description="测试描述",
                    published_at=datetime.utcnow(),
                    audio_url=f"https://example.com/audio{operation_id}.mp3",
                    status="pending"
                )
                session.add(episode)
                await session.commit()

                # 查询数据
                result = await session.execute(
                    select(PodcastEpisode).where(PodcastEpisode.guid == f"test-{operation_id}")
                )
                episode = result.scalar_one_or_none()

                return episode is not None

        # 执行并发操作
        concurrent_operations = 50
        tasks = [db_operation(i) for i in range(concurrent_operations)]

        start_time = time.time()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        total_time = time.time() - start_time

        success_count = sum(1 for r in results if r is True)
        throughput = concurrent_operations / total_time

        print("\n✓ 并发数据库操作:")
        print(f"  - 并发操作数: {concurrent_operations}")
        print(f"  - 成功操作数: {success_count}")
        print(f"  - 总耗时: {total_time:.3f}s")
        print(f"  - 吞吐量: {throughput:.1f} 操作/秒")

        assert success_count >= concurrent_operations * 0.95, "并发操作成功率过低"


# 性能基准测试
async def run_performance_benchmark():
    """运行性能基准测试"""
    print("=" * 60)
    print("播客功能性能基准测试")
    print("=" * 60)

    async with AsyncClient(app=app, base_url="http://test") as client:
        # 创建测试用户
        async with TestSessionLocal() as session:
            from app.core.security import get_password_hash
            user = User(
                email="benchmark@test.com",
                username="benchmark",
                hashed_password=get_password_hash("test123"),
                is_active=True,
                is_verified=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            token = create_access_token(data={"sub": str(user.id)})
            auth_headers = {"Authorization": f"Bearer {token}"}

            # 执行所有性能测试
            test_instance = TestPodcastAPIPerformance()

            print("\n1. 订阅创建性能测试")
            await test_instance.test_subscription_creation_performance(client, auth_headers, PerformanceMonitor())

            print("\n2. 单集查询性能测试")
            await test_instance.test_episodes_query_performance(client, auth_headers, PerformanceMonitor())

            print("\n3. 并发测试")
            await test_instance.test_concurrent_subscription_creation(client, auth_headers, PerformanceMonitor())

            print("\n4. 播放进度更新性能测试")
            await test_instance.test_playback_update_performance(client, auth_headers, PerformanceMonitor())

            print("\n5. 搜索性能测试")
            await test_instance.test_search_performance(client, auth_headers, PerformanceMonitor())

            print("\n6. 内存泄漏检测")
            await test_instance.test_memory_leak_detection(client, auth_headers)

    print("\n" + "=" * 60)
    print("性能基准测试完成")
    print("=" * 60)


if __name__ == "__main__":
    # 安装必要的依赖
    import subprocess
    import sys

    required_packages = ["psutil", "statistics"]
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"安装依赖包: {package}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

    # 运行性能基准测试
    asyncio.run(run_performance_benchmark())