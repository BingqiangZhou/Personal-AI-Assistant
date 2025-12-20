import asyncio
import json
from datetime import datetime, timedelta
from app.core.database import get_db_session
from app.domains.podcast.models import PodcastSubscription, PodcastEpisode
from app.domains.podcast.services import PodcastService
from app.core.security import create_access_token
from sqlalchemy import text

async def create_mock_data():
    # 创建测试token
    test_user_id = 'test-user-123'
    token = create_access_token(data={'sub': test_user_id})

    async for db in get_db_session():
        try:
            # 创建模拟播客订阅
            subscription = PodcastSubscription(
                user_id=test_user_id,
                title="测试技术播客",
                description="这是一个用于测试的技术播客",
                source_url="https://example.com/podcast.rss",
                status="active",
                fetch_interval=3600
            )

            db.add(subscription)
            await db.flush()  # 获取subscription.id

            # 创建几个模拟分集
            episodes_data = [
                {
                    "title": "深入理解Flutter状态管理",
                    "description": "本期节目将深入探讨Flutter中的状态管理方案，包括Provider、Riverpod、Bloc等主流方案的对比分析。",
                    "audio_url": "https://example.com/audio/episode1.mp3",
                    "audio_duration": 1800,  # 30分钟
                    "published_at": datetime.now() - timedelta(days=2),
                    "ai_summary": "本节目详细介绍了Flutter状态管理的各种方案，包括Provider、Riverpod和Bloc的优缺点对比，帮助开发者选择合适的方案。",
                    "transcript_content": "大家好，欢迎收听测试技术播客...",
                    "season": 1,
                    "episode_number": 1
                },
                {
                    "title": "Go语言并发编程实战",
                    "description": "通过实际案例学习Go语言的并发编程特性，包括goroutine、channel和sync包的使用。",
                    "audio_url": "https://example.com/audio/episode2.mp3",
                    "audio_duration": 2400,  # 40分钟
                    "published_at": datetime.now() - timedelta(days=1),
                    "ai_summary": "本节目通过实战案例讲解了Go语言的并发编程，重点介绍了goroutine的使用、channel的通信机制以及sync包中的同步工具。",
                    "transcript_content": "今天我们来聊聊Go语言的并发编程...",
                    "season": 1,
                    "episode_number": 2
                },
                {
                    "title": "构建可扩展的微服务架构",
                    "description": "探讨如何设计和管理可扩展的微服务架构，包括服务发现、负载均衡、熔断器等模式。",
                    "audio_url": "https://example.com/audio/episode3.mp3",
                    "audio_duration": 2700,  # 45分钟
                    "published_at": datetime.now(),
                    "ai_summary": "本节目深入讲解了微服务架构的设计原则，包括服务拆分策略、API网关设计、服务治理等关键概念。",
                    "transcript_content": "微服务架构是现代软件架构的重要模式...",
                    "season": 2,
                    "episode_number": 1
                }
            ]

            for ep_data in episodes_data:
                episode = PodcastEpisode(
                    subscription_id=subscription.id,
                    title=ep_data["title"],
                    description=ep_data["description"],
                    audio_url=ep_data["audio_url"],
                    audio_duration=ep_data["audio_duration"],
                    published_at=ep_data["published_at"],
                    ai_summary=ep_data["ai_summary"],
                    transcript_content=ep_data["transcript_content"],
                    season=ep_data.get("season"),
                    episode_number=ep_data.get("episode_number"),
                    status="published"
                )
                db.add(episode)

            await db.commit()

            print(f"✅ 成功创建测试数据！")
            print(f"订阅ID: {subscription.id}")
            print(f"创建了 {len(episodes_data)} 个播客分集")
            print(f"\n📋 测试信息：")
            print(f"测试用户ID: {test_user_id}")
            print(f"测试Token: {token[:50]}...")
            print(f"\n🌐 访问地址：")
            print(f"前端: http://localhost:3000")
            print(f"后端: http://localhost:8000")

            # 查询验证数据
            result = await db.execute(
                text("SELECT id, title FROM podcast_episodes ORDER BY published_at DESC LIMIT 3")
            )
            episodes = result.fetchall()

            print(f"\n📚 播客列表：")
            for ep in episodes:
                print(f"  - ID:{ep[0]} {ep[1]}")

        except Exception as e:
            print(f"❌ 创建失败: {e}")
            await db.rollback()

if __name__ == "__main__":
    asyncio.run(create_mock_data())