"""
播客后台任务 - Celery Tasks
处理RSS Feed自动抓取、音频转录、AI摘要生成等后台任务
"""

import logging
from typing import List, Optional
from datetime import datetime, timedelta
from celery import Celery

from app.core.config import settings
from app.domains.podcast.services import PodcastService
from app.domains.podcast.repositories import PodcastRepository
from app.core.database import get_db_session
from app.integration.podcast.secure_rss_parser import SecureRSSParser

logger = logging.getLogger(__name__)

# 创建Celery实例
celery_app = Celery(
    "podcast_tasks",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND
)

# Celery配置
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # 任务路由
    task_routes={
        "app.domains.podcast.tasks.refresh_all_podcast_feeds": {"queue": "podcast"},
        "app.domains.podcast.tasks.generate_pending_summaries": {"queue": "ai"},
        "app.domains.podcast.tasks.process_audio_transcription": {"queue": "transcription"},
    },
    # 任务配置
    task_track_started=True,
    task_time_limit=30 * 60,  # 30分钟超时
    task_soft_time_limit=25 * 60,  # 25分钟软超时
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)


@celery_app.task(bind=True, max_retries=3)
def refresh_all_podcast_feeds(self):
    """
    定时任务：刷新所有播客RSS Feed
    每小时执行一次
    """
    logger.info("开始刷新所有播客RSS Feed")

    try:
        # 获取数据库会话
        db = get_db_session()

        # 获取所有需要刷新的订阅
        repo = PodcastRepository(db)

        # 获取所有活跃的播客订阅
        from app.domains.subscription.models import Subscription
        from sqlalchemy import select

        stmt = select(Subscription).where(
            Subscription.source_type == "podcast-rss"
        ).where(
            # 只刷新需要更新的订阅（根据last_fetched_at和fetch_interval）
            or_(
                Subscription.last_fetched_at.is_(None),
                Subscription.last_fetched_at <= datetime.utcnow() - timedelta(minutes=Subscription.fetch_interval)
            )
        )

        result = await db.execute(stmt)
        subscriptions = list(result.scalars().all())

        refreshed_count = 0
        new_episodes_count = 0

        for sub in subscriptions:
            try:
                # 为每个订阅创建服务实例
                service = PodcastService(db, sub.user_id)

                # 刷新订阅
                new_episodes = await service.refresh_subscription(sub.id)

                refreshed_count += 1
                new_episodes_count += len(new_episodes)

                logger.info(f"刷新订阅 {sub.title}: {len(new_episodes)} 期新节目")

            except Exception as e:
                logger.error(f"刷新订阅 {sub.id} 失败: {e}")
                # 继续处理其他订阅
                continue

        await db.close()

        logger.info(f"RSS Feed刷新完成: {refreshed_count} 个订阅, {new_episodes_count} 期新节目")

        return {
            "status": "success",
            "refreshed_subscriptions": refreshed_count,
            "new_episodes": new_episodes_count,
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"刷新RSS Feed失败: {e}")

        # 重试逻辑
        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))

        raise


@celery_app.task(bind=True, max_retries=3)
def generate_pending_summaries(self):
    """
    定时任务：生成待处理的AI摘要
    每30分钟执行一次
    """
    logger.info("开始生成待处理的AI摘要")

    try:
        db = get_db_session()
        repo = PodcastRepository(db)

        # 获取所有待总结的单集
        pending_episodes = await repo.get_unsummarized_episodes()

        processed_count = 0
        failed_count = 0

        for episode in pending_episodes:
            try:
                # 获取订阅信息以获取user_id
                from app.domains.subscription.models import Subscription
                stmt = select(Subscription).where(Subscription.id == episode.subscription_id)
                result = await db.execute(stmt)
                subscription = result.scalar_one_or_none()

                if not subscription:
                    logger.error(f"找不到订阅 {episode.subscription_id}")
                    continue

                # 创建服务实例
                service = PodcastService(db, subscription.user_id)

                # 生成摘要
                summary = await service._generate_summary(episode)

                processed_count += 1
                logger.info(f"生成摘要成功: {episode.title}")

            except Exception as e:
                failed_count += 1
                logger.error(f"生成摘要失败 {episode.id}: {e}")
                # 标记为失败
                await repo.mark_summary_failed(episode.id, str(e))
                continue

        await db.close()

        logger.info(f"AI摘要生成完成: {processed_count} 成功, {failed_count} 失败")

        return {
            "status": "success",
            "processed": processed_count,
            "failed": failed_count,
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"生成AI摘要失败: {e}")

        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))

        raise


@celery_app.task(bind=True, max_retries=3)
def process_audio_transcription(self, episode_id: int, audio_url: str):
    """
    处理音频转录任务
    使用外部转录服务（如OpenAI Whisper）转录音频
    """
    logger.info(f"开始处理音频转录: episode {episode_id}")

    try:
        db = get_db_session()
        repo = PodcastRepository(db)

        # 获取单集信息
        episode = await repo.get_episode_by_id(episode_id)
        if not episode:
            raise ValueError(f"Episode {episode_id} not found")

        # TODO: 集成实际的转录服务
        # 这里使用模拟转录，实际应该调用Whisper API或其他服务

        # 模拟转录过程
        transcription_text = _simulate_transcription(episode.title, episode.description)

        # 保存转录结果
        episode.transcript_content = transcription_text
        episode.transcript_url = f"transcript://episode/{episode_id}"
        await db.commit()

        logger.info(f"音频转录完成: episode {episode_id}")

        # 触发AI摘要生成（如果还没有）
        if not episode.ai_summary:
            from app.domains.subscription.models import Subscription
            stmt = select(Subscription).where(Subscription.id == episode.subscription_id)
            result = await db.execute(stmt)
            subscription = result.scalar_one_or_none()

            if subscription:
                # 异步触发摘要生成
                generate_summary_for_episode.delay(episode.id, subscription.user_id)

        await db.close()

        return {
            "status": "success",
            "episode_id": episode_id,
            "transcription_length": len(transcription_text),
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"音频转录失败 {episode_id}: {e}")

        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))

        raise


@celery_app.task
def generate_summary_for_episode(episode_id: int, user_id: int):
    """
    为指定单集生成AI摘要
    可以被其他任务调用
    """
    logger.info(f"开始生成单集摘要: episode {episode_id}, user {user_id}")

    try:
        db = get_db_session()
        service = PodcastService(db, user_id)

        # 生成摘要
        summary = await service._generate_summary_task(
            await service.repo.get_episode_by_id(episode_id)
        )

        await db.close()

        return {
            "status": "success",
            "episode_id": episode_id,
            "summary": summary,
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"生成单集摘要失败 {episode_id}: {e}")
        raise


@celery_app.task
def cleanup_old_playback_states():
    """
    清理任务：清理旧的播放状态记录
    每天执行一次，保留最近90天的记录
    """
    logger.info("开始清理旧的播放状态记录")

    try:
        db = get_db_session()
        repo = PodcastRepository(db)

        # 删除90天前的播放记录
        cutoff_date = datetime.utcnow() - timedelta(days=90)

        from app.domains.podcast.models import PodcastPlaybackState
        from sqlalchemy import delete

        stmt = delete(PodcastPlaybackState).where(
            PodcastPlaybackState.last_updated_at < cutoff_date
        )

        result = await db.execute(stmt)
        deleted_count = result.rowcount
        await db.commit()

        await db.close()

        logger.info(f"清理完成: 删除 {deleted_count} 条旧记录")

        return {
            "status": "success",
            "deleted_count": deleted_count,
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"清理旧记录失败: {e}")
        raise


@celery_app.task
def generate_podcast_recommendations():
    """
    推荐任务：为所有用户生成播客推荐
    每天执行一次
    """
    logger.info("开始生成播客推荐")

    try:
        db = get_db_session()

        # 获取所有用户
        from app.domains.user.models import User
        from sqlalchemy import select

        stmt = select(User).where(User.is_active == True)
        result = await db.execute(stmt)
        users = list(result.scalars().all())

        recommendations_generated = 0

        for user in users:
            try:
                service = PodcastService(db, user.id)
                recommendations = await service.get_recommendations(limit=20)

                # TODO: 将推荐结果保存到推荐表或缓存中

                recommendations_generated += len(recommendations)

            except Exception as e:
                logger.error(f"为用户 {user.id} 生成推荐失败: {e}")
                continue

        await db.close()

        logger.info(f"推荐生成完成: {recommendations_generated} 条推荐")

        return {
            "status": "success",
            "recommendations_generated": recommendations_generated,
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"生成推荐失败: {e}")
        raise


# === 辅助函数 ===

def _simulate_transcription(title: str, description: str) -> str:
    """
    模拟音频转录
    实际应用中应该调用真实的转录服务
    """
    # 基于标题和描述生成模拟转录文本
    mock_transcription = f"""
    播客标题: {title}

    转录内容:
    欢迎收听本期节目。今天我们将讨论关于 {title} 的话题。

    {description[:500] if description else "本期节目内容精彩，请收听完整音频。"}

    感谢您的收听，我们下期再见。

    （注意：这是模拟转录文本，实际应用中应使用真实的音频转录服务）
    """

    return mock_transcription.strip()


# === Celery Beat 定时任务配置 ===

# 配置定时任务
celery_app.conf.beat_schedule = {
    # 每小时刷新RSS Feed
    'refresh-podcast-feeds': {
        'task': 'app.domains.podcast.tasks.refresh_all_podcast_feeds',
        'schedule': 3600.0,  # 1小时
        'options': {'queue': 'podcast'}
    },

    # 每30分钟生成待处理的AI摘要
    'generate-pending-summaries': {
        'task': 'app.domains.podcast.tasks.generate_pending_summaries',
        'schedule': 1800.0,  # 30分钟
        'options': {'queue': 'ai'}
    },

    # 每天凌晨2点清理旧记录
    'cleanup-old-records': {
        'task': 'app.domains.podcast.tasks.cleanup_old_playback_states',
        'schedule': 86400.0,  # 24小时
        'options': {'queue': 'cleanup'}
    },

    # 每天凌晨3点生成推荐
    'generate-recommendations': {
        'task': 'app.domains.podcast.tasks.generate_podcast_recommendations',
        'schedule': 86400.0,  # 24小时
        'options': {'queue': 'recommendation'}
    },
}