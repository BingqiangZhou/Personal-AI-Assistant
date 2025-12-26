"""
播客后台任务 - Celery Tasks
处理RSS Feed自动抓取、音频转录、AI摘要生成等后台任务
"""

import logging
from typing import List, Optional
from datetime import datetime, timedelta
from celery import Celery
from celery.schedules import crontab
from celery.signals import after_setup_logger
from sqlalchemy import select, delete

# 初始化日志系统
from app.core.logging_config import setup_logging_from_env
setup_logging_from_env()

from app.core.config import settings
from app.domains.podcast.services import PodcastService
from app.domains.podcast.repositories import PodcastRepository
from app.core.database import get_db_session
from app.integration.podcast.secure_rss_parser import SecureRSSParser
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.podcast.transcription_state import get_transcription_state_manager
from app.core.database import async_session_factory

# Import all models to ensure SQLAlchemy relationships are properly resolved
# This is critical for Celery workers which don't call init_db()
from app.domains.user.models import User, UserSession
from app.domains.subscription.models import (
    Subscription, SubscriptionItem, SubscriptionCategory,
    SubscriptionCategoryMapping, SubscriptionType, SubscriptionStatus,
    UpdateFrequency
)
from app.domains.knowledge.models import (
    KnowledgeBase, Document, DocumentTag, SearchHistory
)
from app.domains.assistant.models import (
    Conversation, Message, PromptTemplate, AssistantTask
)
from app.domains.multimedia.models import MediaFile, ProcessingJob
from app.domains.podcast.models import (
    PodcastEpisode, PodcastPlaybackState, TranscriptionTask,
    TranscriptionStatus
)
from app.domains.ai.models import AIModelConfig

import asyncio

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
    每分钟执行一次，检查哪些订阅需要根据其调度配置进行更新
    
    支持的调度频率：
    - HOURLY: 每N小时更新一次（使用fetch_interval）
    - DAILY: 每天在指定时间更新（使用update_time）
    - WEEKLY: 每周指定星期和时间更新（使用update_day_of_week和update_time）
    """
    logger.info("开始刷新所有播客RSS Feed")

    async def _do_refresh():
        async with async_session_factory() as db:
            try:
                # 获取所有需要刷新的订阅
                repo = PodcastRepository(db)

                # 获取所有活跃的播客订阅
                # from app.domains.subscription.models import Subscription # Redundant local import removed

                # Get active podcast subscriptions that should be updated now
                stmt = select(Subscription).where(
                    Subscription.source_type == "podcast-rss"
                ).where(
                    Subscription.status == "active"
                )

                result = await db.execute(stmt)
                all_subscriptions = list(result.scalars().all())

                # Filter subscriptions that should be updated now based on their schedule
                subscriptions = [sub for sub in all_subscriptions if sub.should_update_now()]

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

                        # service.refresh_subscription already logs progress
                        await service.refresh_subscription(sub.id)

                    except Exception as e:
                        logger.error(f"刷新订阅 {sub.id} 失败: {e}")
                        # 继续处理其他订阅
                        continue

                logger.info(f"RSS Feed刷新完成: {refreshed_count} 个订阅, {new_episodes_count} 期新节目")

                return {
                    "status": "success",
                    "refreshed_subscriptions": refreshed_count,
                    "new_episodes": new_episodes_count,
                    "processed_at": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"刷新RSS Feed失败: {e}")
                raise

    try:
        # Run async code in sync Celery worker
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_do_refresh())
        finally:
            loop.close()

        return result

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

    async def _do_generate():
        async with async_session_factory() as db:
            try:
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

                logger.info(f"AI摘要生成完成: {processed_count} 成功, {failed_count} 失败")

                return {
                    "status": "success",
                    "processed": processed_count,
                    "failed": failed_count,
                    "processed_at": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"生成AI摘要失败: {e}")
                raise

    try:
        # Run async code in sync Celery worker
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_do_generate())
        finally:
            loop.close()

        return result

    except Exception as e:
        logger.error(f"生成AI摘要失败: {e}")

        if self.request.retries < self.max_retries:
            raise self.retry(countdown=60 * (2 ** self.request.retries))

        raise


@celery_app.task(bind=True, max_retries=3)
def process_audio_transcription(self, task_id: int, config_db_id: Optional[int] = None):
    """
    处理音频转录任务
    使用外部转录服务（如OpenAI Whisper）转录音频

    集成Redis状态管理:
    - 任务启动时验证并更新锁
    - 执行过程中更新Redis缓存进度
    - 完成或失败时清理Redis状态
    """
    logger.info(f"🎬 [CELERY] 开始处理音频转录任务: task_id={task_id}, config_id={config_db_id}")

    async def _do_transcription():
        # 创建新的数据库引擎（避免fork进程后事件循环冲突）
        from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
        from app.core.config import settings

        # 为Celery worker创建独立的数据库引擎（使用NullPool避免fork后连接池问题）
        worker_engine = create_async_engine(
            settings.DATABASE_URL,
            pool_pre_ping=True,
            pool_size=5,
            max_overflow=10,
            pool_recycle=3600,
            connect_args={
                "server_settings": {
                    "application_name": "celery-worker",
                    "client_encoding": "utf8"
                },
                "timeout": settings.DATABASE_CONNECT_TIMEOUT
            }
        )

        # 创建worker专用的session factory
        worker_session_factory = async_sessionmaker(
            worker_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

        try:
            async with worker_session_factory() as session:
                state_manager = await get_transcription_state_manager()

                try:
                    # Get task info to verify episode_id
                    from app.domains.podcast.models import TranscriptionTask

                    stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
                    result = await session.execute(stmt)
                    task = result.scalar_one_or_none()

                    if not task:
                        logger.error(f"❌ [CELERY] Transcription task {task_id} not found")
                        return

                    episode_id = task.episode_id

                    # Try to acquire lock - only one worker should execute this task
                    lock_acquired = await state_manager.acquire_task_lock(episode_id, task_id, expire_seconds=3600)
                    if not lock_acquired:
                        # Another worker already owns the lock
                        locked_task_id = await state_manager.is_episode_locked(episode_id)
                        logger.info(f"🔄 [CELERY] Task {task_id} skipping execution - episode {episode_id} already locked by task {locked_task_id}")
                        return

                    logger.info(f"🔒 [CELERY] Task {task_id} acquired lock for episode {episode_id}")

                    try:
                        # Update Redis initial progress
                        await state_manager.set_task_progress(
                            task_id,
                            "pending",
                            0,
                            "Worker starting transcription process..."
                        )

                        # Execute transcription
                        service = DatabaseBackedTranscriptionService(session)

                        # Patch the service to update Redis progress during execution
                        original_update = service._update_task_progress_with_session

                        async def redis_update_progress(session, task_id, status, progress, message, error_message=None):
                            # Call original DB update
                            await original_update(session, task_id, status, progress, message, error_message)
                            # Also update Redis cache
                            await state_manager.set_task_progress(task_id, status.value if hasattr(status, 'value') else status, progress, message)

                        # Monkey-patch the progress update method
                        service._update_task_progress_with_session = redis_update_progress

                        # Execute the actual transcription
                        await service.execute_transcription_task(task_id, session, config_db_id)

                        # Clear Redis state on success
                        await state_manager.clear_task_state(task_id, episode_id)

                        logger.info(f"✅ [CELERY] Transcription task {task_id} completed successfully")

                    except Exception as e:
                        logger.error(f"❌ [CELERY] 转录任务执行出错 {task_id}: {e}")
                        import traceback
                        logger.error(traceback.format_exc())

                        # Mark as failed in Redis
                        from app.domains.podcast.models import TranscriptionTask
                        result = await session.execute(stmt)
                        task = result.scalar_one_or_none()

                        if task:
                            await state_manager.fail_task_state(task_id, task.episode_id, str(e))

                        raise
                    finally:
                        # Always release the lock
                        await state_manager.release_task_lock(episode_id, task_id)
                        logger.info(f"🔓 [CELERY] Task {task_id} released lock for episode {episode_id}")

                except Exception as e:
                    logger.error(f"❌ [CELERY] Unexpected error during transcription: {e}")
                    import traceback
                    logger.error(traceback.format_exc())

        finally:
            # 确保关闭worker引擎
            await worker_engine.dispose()

    try:
        # Run async code in sync Celery worker
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_do_transcription())
        finally:
            loop.close()

        return {
            "status": "success",
            "task_id": task_id,
            "processed_at": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"❌ [CELERY] 音频转录任务失败 {task_id}: {e}")

        if self.request.retries < self.max_retries:
            logger.info(f"🔄 [CELERY] Retrying task {task_id} (attempt {self.request.retries + 1}/{self.max_retries})")
            raise self.retry(countdown=60 * (2 ** self.request.retries))

        # Max retries exceeded - mark as permanently failed
        logger.error(f"❌ [CELERY] Task {task_id} failed after {self.max_retries} retries")

        # Try to update Redis state one more time
        async def _mark_failed():
            state_manager = await get_transcription_state_manager()
            async with async_session_factory() as session:
                from app.domains.podcast.models import TranscriptionTask

                stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
                result = await session.execute(stmt)
                task = result.scalar_one_or_none()

                if task:
                    await state_manager.fail_task_state(task_id, task.episode_id, f"Failed after {self.max_retries} retries: {str(e)}")

        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(_mark_failed())
            finally:
                loop.close()
        except Exception as cleanup_error:
            logger.error(f"Failed to mark task as failed in Redis: {cleanup_error}")

        raise


@celery_app.task
def generate_summary_for_episode(episode_id: int, user_id: int):
    """
    为指定单集生成AI摘要
    可以被其他任务调用
    """
    logger.info(f"开始生成单集摘要: episode {episode_id}, user {user_id}")

    async def _do_generate():
        async with async_session_factory() as db:
            try:
                service = PodcastService(db, user_id)

                # 生成摘要
                summary = await service._generate_summary_task(
                    await service.repo.get_episode_by_id(episode_id)
                )

                return {
                    "status": "success",
                    "episode_id": episode_id,
                    "summary": summary,
                    "processed_at": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"生成单集摘要失败 {episode_id}: {e}")
                raise

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_do_generate())
        finally:
            loop.close()

        return result

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

    async def _do_cleanup():
        async with async_session_factory() as db:
            try:
                # 删除90天前的播放记录
                cutoff_date = datetime.utcnow() - timedelta(days=90)

                from app.domains.podcast.models import PodcastPlaybackState

                stmt = delete(PodcastPlaybackState).where(
                    PodcastPlaybackState.last_updated_at < cutoff_date
                )

                result = await db.execute(stmt)
                deleted_count = result.rowcount
                await db.commit()

                logger.info(f"清理完成: 删除 {deleted_count} 条旧记录")

                return {
                    "status": "success",
                    "deleted_count": deleted_count,
                    "processed_at": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"清理旧记录失败: {e}")
                raise

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_do_cleanup())
        finally:
            loop.close()

        return result

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

    async def _do_generate():
        async with async_session_factory() as db:
            try:
                # 获取所有用户
                from app.domains.user.models import User

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

                logger.info(f"推荐生成完成: {recommendations_generated} 条推荐")

                return {
                    "status": "success",
                    "recommendations_generated": recommendations_generated,
                    "processed_at": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"生成推荐失败: {e}")
                raise

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_do_generate())
        finally:
            loop.close()

        return result

    except Exception as e:
        logger.error(f"生成推荐失败: {e}")
        raise


@celery_app.task
def cleanup_old_transcription_temp_files(days: int = 7):
    """
    清理任务：清理旧的转录临时文件
    每天执行一次，清理超过指定天数的失败/已取消任务的临时文件

    Args:
        days: 保留天数，默认7天
    """
    logger.info(f"开始清理旧转录临时文件 (保留 {days} 天)")

    async def _do_cleanup():
        async with async_session_factory() as db:
            try:
                from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService

                service = DatabaseBackedTranscriptionService(db)
                result = await service.cleanup_old_temp_files(days=days)

                return {
                    "status": "success",
                    **result,
                    "processed_at": datetime.utcnow().isoformat()
                }

            except Exception as e:
                logger.error(f"清理临时文件失败: {e}")
                raise

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(_do_cleanup())
        finally:
            loop.close()

        return result

    except Exception as e:
        logger.error(f"清理临时文件失败: {e}")
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
    # Check for subscriptions to update every hour (on the hour)
    'refresh-podcast-feeds': {
        'task': 'app.domains.podcast.tasks.refresh_all_podcast_feeds',
        'schedule': crontab(minute=0),  # Top of every hour
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

    # 每天凌晨4点清理旧的转录临时文件（在清理旧记录和生成推荐之后）
    'cleanup-transcription-temp-files': {
        'task': 'app.domains.podcast.tasks.cleanup_old_transcription_temp_files',
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