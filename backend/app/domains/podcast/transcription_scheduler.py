"""
播客转录调度服务

提供自动化的转录调度功能：
1. 定时检查并转录新分集
2. 避免重复转录已成功转录的内容
3. 支持自定义调度规则和时间间隔
"""

import asyncio
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationError
from app.domains.podcast.models import (
    PodcastEpisode,
    TranscriptionStatus,
    TranscriptionTask,
)
from app.domains.podcast.transcription_manager import DatabaseBackedTranscriptionService
from app.domains.subscription.models import Subscription


logger = logging.getLogger(__name__)


class ScheduleFrequency(str, Enum):
    """调度频率枚举"""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MANUAL = "manual"  # 手动触发


class TranscriptionScheduler:
    """转录调度器"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.transcription_service = DatabaseBackedTranscriptionService(db)
        self._running = False
        self._tasks: dict[int, asyncio.Task] = {}  # episode_id -> task

    async def schedule_transcription(
        self,
        episode_id: int,
        frequency: ScheduleFrequency = ScheduleFrequency.MANUAL,
        custom_interval: int | None = None,  # 自定义间隔（分钟）
        force: bool = False
    ) -> dict[str, Any]:
        """
        为指定分集安排转录任务

        Args:
            episode_id: 播客单集ID
            frequency: 调度频率
            custom_interval: 自定义间隔（分钟）
            force: 是否强制重新转录（即使已存在转录结果）

        Returns:
            Dict包含转录状态和调度信息
        """
        # 获取分集信息
        episode = await self._get_episode(episode_id)
        if not episode:
            raise ValidationError(f"Episode {episode_id} not found")

        # 检查是否已有转录任务
        existing_task = await self._get_existing_transcription_task(episode_id)

        if existing_task:
            # 如果任务已完成且未强制重新转录
            if existing_task.status == TranscriptionStatus.COMPLETED:
                if not force:
                    return {
                        "status": "skipped",
                        "message": "Transcription already exists",
                        "task_id": existing_task.id,
                        "transcript_content": existing_task.transcript_content[:100] + "..." if existing_task.transcript_content else None,
                        "reason": "已存在转录结果，如需重新转录请使用 force=true"
                    }
                else:
                    # Force=true: 删除旧任务，继续创建新任务
                    await self.db.delete(existing_task)
                    await self.db.flush()
                    await self.db.commit()  # Commit to release unique constraint
                    logger.info(f"Deleted existing completed task {existing_task.id} for force re-transcription")

            # 如果任务正在处理中
            elif existing_task.status in [
                TranscriptionStatus.PENDING,
                TranscriptionStatus.DOWNLOADING,
                TranscriptionStatus.CONVERTING,
                TranscriptionStatus.SPLITTING,
                TranscriptionStatus.TRANSCRIBING,
                TranscriptionStatus.MERGING
            ]:
                return {
                    "status": "processing",
                    "message": "Transcription task already in progress",
                    "task_id": existing_task.id,
                    "progress": existing_task.progress_percentage,
                    "current_status": existing_task.status.value
                }

            # 如果任务失败或取消，且未强制重新转录
            elif existing_task.status in [TranscriptionStatus.FAILED, TranscriptionStatus.CANCELLED]:
                if not force:
                    return {
                        "status": "failed",
                        "message": "Previous transcription failed, use force=true to retry",
                        "task_id": existing_task.id,
                        "error": existing_task.error_message,
                        "reason": "上次转录失败，如需重试请使用 force=true"
                    }
                else:
                    # Force=true: 删除旧任务，继续创建新任务
                    await self.db.delete(existing_task)
                    await self.db.flush()
                    await self.db.commit()  # Commit to release unique constraint
                    logger.info(f"Deleted existing failed task {existing_task.id} for retry")

        # 启动转录任务
        try:
            task = await self.transcription_service.start_transcription(episode_id, force=force)

            # 记录调度信息
            schedule_info = {
                "task_id": task.id,
                "episode_id": episode_id,
                "frequency": frequency,
                "custom_interval": custom_interval,
                "scheduled_at": datetime.now(timezone.utc),
                "status": "scheduled"
            }

            logger.info(f"Scheduled transcription for episode {episode_id}, task {task.id}")

            return {
                "status": "scheduled",
                "message": "Transcription task started",
                "task_id": task.id,
                "schedule_info": schedule_info
            }

        except Exception as e:
            logger.error(f"Failed to schedule transcription for episode {episode_id}: {str(e)}")
            raise

    async def batch_schedule_transcription(
        self,
        subscription_id: int,
        frequency: ScheduleFrequency = ScheduleFrequency.DAILY,
        limit: int | None = None,
        skip_existing: bool = True
    ) -> list[dict[str, Any]]:
        """
        批量为订阅的所有分集安排转录

        Args:
            subscription_id: 订阅ID
            frequency: 调度频率
            limit: 最大处理数量
            skip_existing: 跳过已存在转录的分集

        Returns:
            List of scheduling results
        """
        # 获取订阅的所有分集
        stmt = select(PodcastEpisode).where(
            PodcastEpisode.subscription_id == subscription_id
        ).order_by(PodcastEpisode.published_at.desc())

        if limit:
            stmt = stmt.limit(limit)

        result = await self.db.execute(stmt)
        episodes = result.scalars().all()

        if not episodes:
            return []

        results = []
        for episode in episodes:
            try:
                # 检查是否已存在转录
                existing = await self._get_existing_transcription_task(episode.id)
                if skip_existing and existing and existing.status == TranscriptionStatus.COMPLETED:
                    results.append({
                        "episode_id": episode.id,
                        "episode_title": episode.title,
                        "status": "skipped",
                        "reason": "Already transcribed"
                    })
                    continue

                # 安排转录
                result = await self.schedule_transcription(
                    episode_id=episode.id,
                    frequency=frequency,
                    force=False
                )
                result["episode_id"] = episode.id
                result["episode_title"] = episode.title
                results.append(result)

            except Exception as e:
                results.append({
                    "episode_id": episode.id,
                    "episode_title": episode.title,
                    "status": "error",
                    "error": str(e)
                })

        return results

    async def check_and_transcribe_new_episodes(
        self,
        subscription_id: int,
        hours_since_published: int = 24
    ) -> dict[str, Any]:
        """
        检查并转录新发布的分集

        Args:
            subscription_id: 订阅ID
            hours_since_published: 检查多少小时内发布的分集

        Returns:
            调度结果统计
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours_since_published)

        # 获取新分集
        stmt = select(PodcastEpisode).where(
            and_(
                PodcastEpisode.subscription_id == subscription_id,
                PodcastEpisode.published_at >= cutoff_time,
                or_(
                    PodcastEpisode.transcript_content.is_(None),
                    PodcastEpisode.transcript_content == ''
                )
            )
        ).order_by(PodcastEpisode.published_at.desc())

        result = await self.db.execute(stmt)
        new_episodes = result.scalars().all()

        if not new_episodes:
            return {
                "status": "completed",
                "message": "No new episodes found",
                "processed": 0,
                "skipped": 0
            }

        # 批量安排转录
        results = []
        for episode in new_episodes:
            try:
                result = await self.schedule_transcription(
                    episode_id=episode.id,
                    frequency=ScheduleFrequency.MANUAL,
                    force=False
                )
                results.append({
                    "episode_id": episode.id,
                    "status": "scheduled",
                    "task_id": result.get("task_id")
                })
            except Exception as e:
                results.append({
                    "episode_id": episode.id,
                    "status": "error",
                    "error": str(e)
                })

        scheduled = sum(1 for r in results if r["status"] == "scheduled")
        errors = sum(1 for r in results if r["status"] == "error")

        return {
            "status": "completed",
            "message": f"Scheduled {scheduled} new episodes for transcription",
            "processed": len(new_episodes),
            "scheduled": scheduled,
            "errors": errors,
            "details": results
        }

    async def get_transcription_status(self, episode_id: int) -> dict[str, Any]:
        """获取指定分集的转录状态"""
        episode = await self._get_episode(episode_id)
        if not episode:
            raise ValidationError(f"Episode {episode_id} not found")

        task = await self._get_existing_transcription_task(episode_id)

        if not task:
            return {
                "episode_id": episode_id,
                "episode_title": episode.title,
                "status": "not_started",
                "has_transcript": episode.transcript_content is not None,
                "transcript_preview": episode.transcript_content[:100] + "..." if episode.transcript_content else None
            }

        result = {
            "episode_id": episode_id,
            "episode_title": episode.title,
            "task_id": task.id,
            "status": task.status.value,
            "progress": task.progress_percentage,
            "created_at": task.created_at,
            "updated_at": task.updated_at,
            "completed_at": task.completed_at,
            "has_transcript": task.transcript_content is not None,
            "transcript_word_count": task.transcript_word_count,
            "has_summary": task.summary_content is not None,
            "summary_word_count": task.summary_word_count,
            "error_message": task.error_message
        }

        if task.status == TranscriptionStatus.COMPLETED:
            result["transcript_preview"] = task.transcript_content[:100] + "..." if task.transcript_content else None

        return result

    async def get_pending_transcriptions(self) -> list[dict[str, Any]]:
        """获取所有待处理的转录任务"""
        stmt = select(TranscriptionTask).where(
            TranscriptionTask.status.in_([
                TranscriptionStatus.PENDING,
                TranscriptionStatus.DOWNLOADING,
                TranscriptionStatus.CONVERTING,
                TranscriptionStatus.SPLITTING,
                TranscriptionStatus.TRANSCRIBING,
                TranscriptionStatus.MERGING
            ])
        ).order_by(TranscriptionTask.created_at.desc())

        result = await self.db.execute(stmt)
        tasks = result.scalars().all()

        return [{
            "task_id": task.id,
            "episode_id": task.episode_id,
            "status": task.status.value,
            "progress": task.progress_percentage,
            "created_at": task.created_at,
            "updated_at": task.updated_at
        } for task in tasks]

    async def cancel_transcription(self, episode_id: int) -> bool:
        """取消转录任务"""
        task = await self._get_existing_transcription_task(episode_id)
        if not task:
            return False

        return await self.transcription_service.cancel_transcription(task.id)

    async def get_transcript_from_existing(self, episode_id: int) -> str | None:
        """
        从已存在的转录结果中获取文本

        这是用户要求的核心功能：如果已成功转录，直接读取文本而不重新转录
        """
        # 1. 检查PodcastEpisode中的transcript_content
        episode = await self._get_episode(episode_id)
        if episode and episode.transcript_content:
            return episode.transcript_content

        # 2. 检查TranscriptionTask中的transcript_content
        task = await self._get_existing_transcription_task(episode_id)
        if task and task.status == TranscriptionStatus.COMPLETED and task.transcript_content:
            return task.transcript_content

        return None

    async def _get_episode(self, episode_id: int) -> PodcastEpisode | None:
        """获取播客单集"""
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_existing_transcription_task(self, episode_id: int) -> TranscriptionTask | None:
        """获取已存在的转录任务"""
        stmt = select(TranscriptionTask).where(TranscriptionTask.episode_id == episode_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()


class AutomatedTranscriptionScheduler:
    """自动化转录调度器（后台运行）"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.scheduler = TranscriptionScheduler(db)
        self._running = False
        self._background_task: asyncio.Task | None = None

    async def start(
        self,
        check_interval_minutes: int = 60,
        hours_since_published: int = 24
    ):
        """
        启动自动化调度

        Args:
            check_interval_minutes: 检查间隔（分钟）
            hours_since_published: 检查多少小时内发布的分集
        """
        if self._running:
            logger.warning("Automated scheduler already running")
            return

        self._running = True
        self._background_task = asyncio.create_task(
            self._run_scheduler(check_interval_minutes, hours_since_published)
        )

        logger.info(f"Started automated transcription scheduler (interval: {check_interval_minutes}min)")

    async def stop(self):
        """停止自动化调度"""
        self._running = False
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
        logger.info("Stopped automated transcription scheduler")

    async def _run_scheduler(self, interval_minutes: int, hours_since_published: int):
        """后台调度循环"""
        while self._running:
            try:
                # 获取所有播客订阅
                stmt = select(Subscription).where(
                    Subscription.source_type == "podcast-rss"
                )
                result = await self.db.execute(stmt)
                subscriptions = result.scalars().all()

                for subscription in subscriptions:
                    try:
                        # 检查并转录新分集
                        result = await self.scheduler.check_and_transcribe_new_episodes(
                            subscription_id=subscription.id,
                            hours_since_published=hours_since_published
                        )

                        if result["scheduled"] > 0:
                            logger.info(
                                f"Subscription {subscription.id} ({subscription.title}): "
                                f"Scheduled {result['scheduled']} new episodes for transcription"
                            )

                    except Exception as e:
                        logger.error(f"Error processing subscription {subscription.id}: {str(e)}")

                # 等待下一次检查
                await asyncio.sleep(interval_minutes * 60)

            except Exception as e:
                logger.error(f"Scheduler error: {str(e)}")
                await asyncio.sleep(interval_minutes * 60)  # 出错后等待重试


# 便捷函数
async def schedule_episode_transcription(
    db: AsyncSession,
    episode_id: int,
    force: bool = False
) -> dict[str, Any]:
    """便捷函数：为单个分集安排转录"""
    scheduler = TranscriptionScheduler(db)
    return await scheduler.schedule_transcription(episode_id, force=force)


async def get_episode_transcript(
    db: AsyncSession,
    episode_id: int
) -> str | None:
    """便捷函数：获取分集转录文本（避免重复转录）"""
    scheduler = TranscriptionScheduler(db)
    return await scheduler.get_transcript_from_existing(episode_id)


async def batch_transcribe_subscription(
    db: AsyncSession,
    subscription_id: int,
    skip_existing: bool = True
) -> dict[str, Any]:
    """便捷函数：批量转录订阅的所有分集"""
    scheduler = TranscriptionScheduler(db)
    results = await scheduler.batch_schedule_transcription(
        subscription_id=subscription_id,
        skip_existing=skip_existing
    )

    return {
        "subscription_id": subscription_id,
        "total": len(results),
        "scheduled": sum(1 for r in results if r.get("status") == "scheduled"),
        "skipped": sum(1 for r in results if r.get("status") == "skipped"),
        "errors": sum(1 for r in results if r.get("status") == "error"),
        "details": results
    }
