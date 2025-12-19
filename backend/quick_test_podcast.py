#!/usr/bin/env python3
"""
播客功能快速测试脚本
使用示例RSS feed快速验证核心功能
"""

import asyncio
import sys
import os
from datetime import datetime
from pathlib import Path

# 添加项目路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# 测试配置
TEST_RSS_URL = "https://feed.xyzfm.space/mcklbwxjdvfu"
TEST_PODCAST_NAME = "XYZ FM 播客测试"


async def test_rss_parsing():
    """测试RSS解析功能"""
    print("\n1. 测试RSS解析...")
    print("-" * 40)

    try:
        import feedparser

        print(f"正在解析RSS: {TEST_RSS_URL}")
        feed = feedparser.parse(TEST_RSS_URL)

        if feed.bozo == 0:
            print(f"✅ RSS解析成功")
            print(f"   播客标题: {feed.feed.get('title', 'Unknown')}")
            print(f"   描述: {feed.feed.get('description', 'No description')[:100]}...")
            print(f"   单集数量: {len(feed.entries)}")

            # 显示前3个单集
            for i, entry in enumerate(feed.entries[:3]):
                print(f"\n   单集 {i+1}:")
                print(f"     标题: {entry.get('title', 'No title')[:50]}")
                print(f"   发布时间: {entry.get('published', 'Unknown')}")
                if entry.get('enclosures'):
                    audio_url = entry.enclosures[0].get('href', '')
                    print(f"   音频URL: {audio_url[:50]}...")
        else:
            print(f"❌ RSS解析失败: {feed.bozo_exception}")
            return False

        return True
    except Exception as e:
        print(f"❌ RSS解析错误: {e}")
        return False


async def test_backend_api():
    """测试后端API"""
    print("\n2. 测试后端API...")
    print("-" * 40)

    try:
        from httpx import AsyncClient
        from app.core.security import create_access_token
        from app.domains.user.models import User
        from app.core.test_database import TestSessionLocal, get_test_db
        from app.core.database import test_engine
        from sqlalchemy.ext.asyncio import AsyncSession

        # 设置测试数据库
        from app.main import app
        app.dependency_overrides[get_db_session] = get_test_db

        # 创建测试数据库
        async with test_engine.begin() as conn:
            from app.core.database import Base
            await conn.run_sync(Base.metadata.create_all)

        # 创建测试用户
        async with TestSessionLocal() as session:
            from app.core.security import get_password_hash
            user = User(
                email="test@podcast.com",
                username="testuser",
                hashed_password=get_password_hash("testpass123"),
                is_active=True,
                is_verified=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            # 生成JWT token
            token = create_access_token(data={"sub": str(user.id)})
            headers = {"Authorization": f"Bearer {token}"}

            async with AsyncClient(app=app, base_url="http://test") as client:
                # 测试添加播客订阅
                print("添加播客订阅...")
                subscription_data = {
                    "feed_url": TEST_RSS_URL,
                    "custom_name": TEST_PODCAST_NAME,
                    "category_ids": [1]
                }

                response = await client.post(
                    "/api/v1/podcasts/subscriptions",
                    json=subscription_data,
                    headers=headers
                )

                if response.status_code == 201:
                    data = response.json()
                    subscription_id = data["id"]
                    episode_count = data["episode_count"]
                    print(f"✅ 订阅创建成功")
                    print(f"   订阅ID: {subscription_id}")
                    print(f"   获取单集数: {episode_count}")

                    # 测试获取单集列表
                    print("\n获取单集列表...")
                    response = await client.get(
                        f"/api/v1/podcasts/episodes?subscription_id={subscription_id}",
                        headers=headers
                    )

                    if response.status_code == 200:
                        episodes_data = response.json()
                        episodes = episodes_data.get("episodes", [])
                        print(f"✅ 单集列表获取成功")
                        print(f"   单集总数: {len(episodes)}")

                        if episodes:
                            # 测试获取单集详情
                            episode_id = episodes[0]["id"]
                            print(f"\n获取单集详情 (ID: {episode_id})...")
                            response = await client.get(
                                f"/api/v1/podcasts/episodes/{episode_id}",
                                headers=headers
                            )

                            if response.status_code == 200:
                                episode_detail = response.json()
                                print(f"✅ 单集详情获取成功")
                                print(f"   标题: {episode_detail.get('title', 'No title')[:50]}")
                                print(f"   时长: {episode_detail.get('audio_duration', 'Unknown')} 秒")

                                # 测试播放进度更新
                                print("\n更新播放进度...")
                                progress_data = {
                                    "current_position": 60,  # 1分钟
                                    "is_playing": True,
                                    "playback_rate": 1.0
                                }

                                response = await client.post(
                                    f"/api/v1/podcasts/episodes/{episode_id}/progress",
                                    json=progress_data,
                                    headers=headers
                                )

                                if response.status_code == 200:
                                    playback_state = response.json()
                                    print(f"✅ 播放进度更新成功")
                                    print(f"   当前位置: {playback_state.get('current_position')} 秒")
                                else:
                                    print(f"❌ 播放进度更新失败: {response.status_code}")
                            else:
                                print(f"❌ 单集详情获取失败: {response.status_code}")
                        else:
                            print("⚠️ 没有找到单集")
                    else:
                        print(f"❌ 单集列表获取失败: {response.status_code}")
                else:
                    print(f"❌ 订阅创建失败: {response.status_code}")
                    print(f"   错误信息: {response.text}")
                    return False

        return True

    except Exception as e:
        print(f"❌ API测试错误: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_ai_summary():
    """测试AI摘要功能"""
    print("\n3. 测试AI摘要功能...")
    print("-" * 40)

    try:
        from httpx import AsyncClient
        from app.core.security import create_access_token
        from app.core.test_database import TestSessionLocal
        from app.domains.user.models import User
        from app.core.security import get_password_hash

        # 获取现有的episode
        async with TestSessionLocal() as session:
            user = User(
                email="ai@test.com",
                username="aiuser",
                hashed_password=get_password_hash("testpass123"),
                is_active=True,
                is_verified=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            token = create_access_token(data={"sub": str(user.id)})
            headers = {"Authorization": f"Bearer {token}"}

            async with AsyncClient(app=app, base_url="http://test") as client:
                # 获取单集列表
                response = await client.get(
                    "/api/v1/podcasts/episodes",
                    headers=headers
                )

                if response.status_code == 200:
                    episodes = response.json().get("episodes", [])
                    if episodes:
                        episode_id = episodes[0]["id"]
                        print(f"测试单集 {episode_id} 的AI摘要...")

                        # 请求AI摘要
                        summary_request = {
                            "force_regenerate": False,
                            "language": "zh"
                        }

                        response = await client.post(
                            f"/api/v1/podcasts/episodes/{episode_id}/summary",
                            json=summary_request,
                            headers=headers
                        )

                        if response.status_code in [200, 202]:
                            if response.status_code == 200:
                                summary_data = response.json()
                                if summary_data.get("ai_summary"):
                                    print(f"✅ AI摘要生成成功")
                                    print(f"   摘要: {summary_data['ai_summary'][:100]}...")
                                else:
                                    print("⚠️ AI摘要处理中...")
                            else:
                                print("✅ AI摘要请求已提交，正在处理中...")
                        else:
                            print(f"❌ AI摘要请求失败: {response.status_code}")
                    else:
                        print("⚠️ 没有可用的单集进行AI摘要测试")
                else:
                    print(f"❌ 获取单集列表失败: {response.status_code}")

        return True

    except Exception as e:
        print(f"❌ AI摘要测试错误: {e}")
        return False


async def test_search_functionality():
    """测试搜索功能"""
    print("\n4. 测试搜索功能...")
    print("-" * 40)

    try:
        from httpx import AsyncClient
        from app.core.security import create_access_token
        from app.core.test_database import TestSessionLocal
        from app.domains.user.models import User
        from app.core.security import get_password_hash

        async with TestSessionLocal() as session:
            user = User(
                email="search@test.com",
                username="searchuser",
                hashed_password=get_password_hash("testpass123"),
                is_active=True,
                is_verified=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            token = create_access_token(data={"sub": str(user.id)})
            headers = {"Authorization": f"Bearer {token}"}

            async with AsyncClient(app=app, base_url="http://test") as client:
                # 测试搜索关键词
                search_terms = ["播客", "Podcast", "AI", "技术"]

                for term in search_terms:
                    print(f"\n搜索关键词: '{term}'")
                    response = await client.get(
                        "/api/v1/podcasts/episodes/search",
                        params={"query": term},
                        headers=headers
                    )

                    if response.status_code == 200:
                        search_results = response.json()
                        episodes = search_results.get("episodes", [])
                        print(f"✅ 搜索成功，找到 {len(episodes)} 个结果")
                    else:
                        print(f"❌ 搜索失败: {response.status_code}")

        return True

    except Exception as e:
        print(f"❌ 搜索功能测试错误: {e}")
        return False


async def test_performance_metrics():
    """测试性能指标"""
    print("\n5. 测试性能指标...")
    print("-" * 40)

    try:
        from httpx import AsyncClient
        from app.core.security import create_access_token
        from app.core.test_database import TestSessionLocal
        from app.domains.user.models import User
        from app.core.security import get_password_hash
        import time

        async with TestSessionLocal() as session:
            user = User(
                email="perf@test.com",
                username="perfuser",
                hashed_password=get_password_hash("testpass123"),
                is_active=True,
                is_verified=True
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            token = create_access_token(data={"sub": str(user.id)})
            headers = {"Authorization": f"Bearer {token}"}

            async with AsyncClient(app=app, base_url="http://test") as client:
                # 测试API响应时间
                print("\n测试API响应时间...")
                response_times = []

                for i in range(5):
                    start_time = time.time()
                    response = await client.get(
                        "/api/v1/podcasts/subscriptions",
                        headers=headers
                    )
                    end_time = time.time()

                    if response.status_code == 200:
                        response_times.append(end_time - start_time)

                if response_times:
                    avg_time = sum(response_times) / len(response_times)
                    max_time = max(response_times)
                    print(f"✅ 平均响应时间: {avg_time:.3f}s")
                    print(f"   最大响应时间: {max_time:.3f}s")
                    print(f"   最小响应时间: {min(response_times):.3f}s")

                # 测试并发请求
                print("\n测试并发请求...")
                import asyncio

                tasks = []
                for i in range(10):
                    task = client.get(
                        "/api/v1/podcasts/subscriptions",
                        headers=headers
                    )
                    tasks.append(task)

                start_time = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                end_time = time.time()

                success_count = sum(1 for r in responses if hasattr(r, 'status_code') and r.status_code == 200)
                print(f"✅ 并发测试完成")
                print(f"   成功请求: {success_count}/10")
                print(f"   总耗时: {end_time - start_time:.3f}s")
                print(f"   平均每个请求: {(end_time - start_time) / 10:.3f}s")

        return True

    except Exception as e:
        print(f"❌ 性能测试错误: {e}")
        return False


async def main():
    """主测试函数"""
    print("=" * 60)
    print("播客功能快速测试")
    print("=" * 60)
    print(f"测试时间: {datetime.now()}")
    print(f"测试RSS: {TEST_RSS_URL}")
    print("=" * 60)

    test_results = {
        "RSS解析": False,
        "后端API": False,
        "AI摘要": False,
        "搜索功能": False,
        "性能指标": False,
    }

    # 执行各项测试
    test_results["RSS解析"] = await test_rss_parsing()
    test_results["后端API"] = await test_backend_api()
    test_results["AI摘要"] = await test_ai_summary()
    test_results["搜索功能"] = await test_search_functionality()
    test_results["性能指标"] = await test_performance_metrics()

    # 输出测试结果摘要
    print("\n" + "=" * 60)
    print("测试结果摘要")
    print("=" * 60)

    passed_count = 0
    for test_name, passed in test_results.items():
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"{test_name:12}: {status}")
        if passed:
            passed_count += 1

    print("-" * 60)
    print(f"总测试数: {len(test_results)}")
    print(f"通过: {passed_count}")
    print(f"失败: {len(test_results) - passed_count}")
    print(f"成功率: {(passed_count / len(test_results) * 100):.1f}%")

    # 给出建议
    print("\n建议:")
    if passed_count == len(test_results):
        print("🎉 所有测试通过！播客功能运行良好。")
        print("\n下一步:")
        print("1. 运行完整的测试套件以获得更详细的覆盖率报告")
        print("2. 进行压力测试以验证系统在高负载下的表现")
        print("3. 测试不同的RSS feed以确保兼容性")
    else:
        print("⚠️ 部分测试失败，请检查:")
        for test_name, passed in test_results.items():
            if not passed:
                print(f"   - {test_name}功能")

    print("\n完整测试命令:")
    print("python backend/run_podcast_tests.py")

    return passed_count == len(test_results)


if __name__ == "__main__":
    # 切换到backend目录
    os.chdir(project_root)

    # 运行快速测试
    success = asyncio.run(main())
    sys.exit(0 if success else 1)