"""
播客转录服务管理器
使用数据库中的AI模型配置
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ValidationError
from app.domains.ai.models import ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.podcast.ai_key_resolver import resolve_api_key_with_fallback
from app.domains.podcast.transcription import (
    PodcastTranscriptionService,
    SiliconFlowTranscriber,
)
from app.domains.podcast.transcription_state import get_transcription_state_manager


logger = logging.getLogger(__name__)


class TranscriptionModelManager:
    """转录模型管理器"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_model_repo = AIModelConfigRepository(db)

    async def get_active_transcription_model(self, model_name: str | None = None):
        """获取活跃的转录模型配置（按优先级排序）"""
        if model_name:
            # 根据名称获取指定模型
            model = await self.ai_model_repo.get_by_name(model_name)
            if (
                not model
                or not model.is_active
                or model.model_type != ModelType.TRANSCRIPTION
            ):
                raise ValidationError(
                    f"Transcription model '{model_name}' not found or not active"
                )
            return model
        else:
            # 按优先级获取转录模型列表
            active_models = await self.ai_model_repo.get_active_models_by_priority(
                ModelType.TRANSCRIPTION
            )
            if not active_models:
                raise ValidationError("No active transcription model found")
            # 返回优先级最高的模型（priority 数字最小的）
            return active_models[0]

    async def create_transcriber(self, model_name: str | None = None):
        """创建转录器实例"""
        model_config = await self.get_active_transcription_model(model_name)

        # 解密API密钥
        api_key = await self._get_api_key(model_config)

        # 获取API URL - 如果模型配置的URL为空，使用默认值
        api_url = model_config.api_url
        if not api_url or api_url.strip() == "":
            from app.core.config import settings

            default_url = "https://api.siliconflow.cn/v1/audio/transcriptions"
            api_url = getattr(settings, "TRANSCRIPTION_API_URL", default_url)
            logger.warning(
                f"⚠️ [MODEL] Model {model_config.name} has no api_url configured, using default: {api_url}"
            )
        else:
            logger.info(f"🔗 [MODEL] Using api_url from model config: {api_url}")

        # 根据提供商创建对应的转录器
        if model_config.provider == "siliconflow":
            return SiliconFlowTranscriber(
                api_key=api_key,
                api_url=api_url,
                max_concurrent=model_config.max_concurrent_requests,
            )
        elif model_config.provider == "openai":
            # OpenAI的转录服务API格式类似，可以使用相同的转录器
            return SiliconFlowTranscriber(
                api_key=api_key,
                api_url=api_url,
                max_concurrent=model_config.max_concurrent_requests,
            )
        else:
            # 自定义提供商，尝试使用通用转录器
            return SiliconFlowTranscriber(
                api_key=api_key,
                api_url=api_url,
                max_concurrent=model_config.max_concurrent_requests,
            )

    async def get_model_info(self, model_name: str | None = None) -> dict[str, Any]:
        """获取模型信息"""
        model_config = await self.get_active_transcription_model(model_name)
        return {
            "model_id": model_config.id,
            "name": model_config.name,
            "display_name": model_config.display_name,
            "provider": model_config.provider,
            "model_id_str": model_config.model_id,
            "max_concurrent_requests": model_config.max_concurrent_requests,
            "timeout_seconds": model_config.timeout_seconds,
            "extra_config": model_config.extra_config or {},
        }

    async def list_available_models(self):
        """列出所有可用的转录模型"""
        active_models = await self.ai_model_repo.get_active_models(
            ModelType.TRANSCRIPTION
        )
        return [
            {
                "id": model.id,
                "name": model.name,
                "display_name": model.display_name,
                "provider": model.provider,
                "model_id": model.model_id,
                "is_default": model.is_default,
            }
            for model in active_models
        ]

    async def _get_api_key(self, model_config) -> str:
        """Get API key with system-key preference and active-model fallback."""
        system_key = None
        if model_config.is_system:
            from app.core.config import settings

            if model_config.provider == "openai":
                system_key = getattr(settings, "OPENAI_API_KEY", "")
            elif model_config.provider == "siliconflow":
                system_key = getattr(settings, "TRANSCRIPTION_API_KEY", "")

        active_models = await self.ai_model_repo.get_active_models(
            ModelType.TRANSCRIPTION
        )
        try:
            return resolve_api_key_with_fallback(
                primary_model=model_config,
                fallback_models=active_models,
                logger=logger,
                invalid_message=(
                    f"No valid API key found. Model '{model_config.name}' has a "
                    "placeholder/invalid API key, and no alternative models with "
                    "valid API keys were found. Please configure a valid API key "
                    "for at least one TRANSCRIPTION model."
                ),
                provider_key_prefix={"siliconflow": "sk-"},
                system_key=system_key,
            )
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


class DatabaseBackedTranscriptionService(PodcastTranscriptionService):
    """基于数据库配置的转录服务"""

    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self.model_manager = TranscriptionModelManager(db)

    async def start_transcription(
        self, episode_id: int, model_name: str | None = None, force: bool = False
    ) -> dict[str, Any]:
        """启动或复用转录任务，并返回内部动作元数据。"""
        from app.domains.podcast.models import TranscriptionTask
        from app.domains.podcast.tasks import process_audio_transcription

        # 获取模型信息（验证模型是否存在）
        if model_name:
            await self.model_manager.get_active_transcription_model(model_name)

        stmt = (
            select(TranscriptionTask)
            .where(TranscriptionTask.episode_id == episode_id)
            .order_by(TranscriptionTask.created_at.desc())
        )

        result = await self.db.execute(stmt)
        existing_task = result.scalar_one_or_none()

        state_manager = await get_transcription_state_manager()
        if existing_task and not force:
            status_value = (
                existing_task.status.value
                if hasattr(existing_task.status, "value")
                else str(existing_task.status)
            )

            if status_value == "completed":
                return {"task": existing_task, "action": "reused_completed"}

            if status_value == "in_progress":
                await state_manager.set_episode_task(episode_id, existing_task.id)
                return {"task": existing_task, "action": "reused_in_progress"}

            if status_value == "pending":
                locked_task_id = await state_manager.is_episode_locked(episode_id)
                if locked_task_id == existing_task.id:
                    await state_manager.set_episode_task(episode_id, existing_task.id)
                    return {"task": existing_task, "action": "reused_pending"}
                if locked_task_id is not None:
                    return {"task": existing_task, "action": "locked_by_other_task"}

                config_db_id = await self._resolve_transcription_config_db_id(model_name)
                process_audio_transcription.delay(existing_task.id, config_db_id)
                return {"task": existing_task, "action": "redispatched_pending"}

            if status_value in {"failed", "cancelled"}:
                import os

                temp_episode_dir = os.path.join(self.temp_dir, f"episode_{episode_id}")
                has_temp_files = False
                if os.path.exists(temp_episode_dir):
                    for _, _, files in os.walk(temp_episode_dir):
                        if files:
                            has_temp_files = True
                            break

                if has_temp_files:
                    locked_task_id = await state_manager.is_episode_locked(episode_id)
                    if locked_task_id is None:
                        existing_task.status = "pending"
                        existing_task.error_message = None
                        existing_task.started_at = None
                        existing_task.completed_at = None
                        existing_task.progress_percentage = 0
                        existing_task.current_step = "not_started"
                        await self.db.commit()
                        await self.db.refresh(existing_task)

                        config_db_id = await self._resolve_transcription_config_db_id(
                            model_name
                        )
                        process_audio_transcription.delay(existing_task.id, config_db_id)
                        return {
                            "task": existing_task,
                            "action": "redispatched_failed_with_temp",
                        }
                    return {"task": existing_task, "action": "locked_by_other_task"}

        # 没有可重用的任务，创建新任务
        task, config_db_id = await super().create_transcription_task_record(
            episode_id, model_name, force
        )

        process_audio_transcription.delay(task.id, config_db_id)
        return {"task": task, "action": "created"}

    async def _resolve_transcription_config_db_id(
        self, model_name: str | None
    ) -> int | None:
        """Resolve model config id for dispatch metadata."""
        ai_repo = AIModelConfigRepository(self.db)
        model_config = None
        if model_name:
            model_config = await ai_repo.get_by_name(model_name)
        if not model_config:
            active_models = await ai_repo.get_active_models_by_priority(
                ModelType.TRANSCRIPTION
            )
            model_config = active_models[0] if active_models else None
        return model_config.id if model_config else None

    async def get_transcription_models(self):
        """获取可用的转录模型列表"""
        return await self.model_manager.list_available_models()

    async def delete_episode_transcription(self, episode_id: int) -> int | None:
        """Delete latest transcription task for an episode and return task id."""
        task = await self.get_episode_transcription(episode_id)
        if not task:
            return None
        task_id = task.id
        await self.db.delete(task)
        await self.db.commit()
        return task_id

    async def reset_stale_tasks(self):
        """
        重置所有处于中间状态的任务为失败
        用于服务器重启后清理僵尸任务

        注意：只重置已实际开始执行的任务（started_at 不为空）
        未开始执行的 PENDING 任务保持原状态，可以被重新调度
        """
        from sqlalchemy import and_, update

        from app.domains.podcast.models import TranscriptionTask

        # 任务状态阈值：只重置超过这个时间的任务（5分钟）
        # 避免重置刚刚创建但还没执行的任务
        # Note: Use datetime.now(timezone.utc) to match the database column type (naive datetime)
        stale_threshold = datetime.now(timezone.utc) - timedelta(minutes=5)

        # 只有实际开始执行的任务状态才应该被重置
        # PENDING 状态如果 started_at 为空，说明任务还没开始，不应该被重置
        # 在新模型中，所有进行中的任务都是 in_progress 状态，current_step 记录具体步骤
        in_progress_statuses = ["in_progress"]  # Use string values

        try:
            # 重置已开始执行但超时的任务
            stmt = (
                update(TranscriptionTask)
                .where(
                    and_(
                        TranscriptionTask.status.in_(in_progress_statuses),
                        TranscriptionTask.started_at.isnot(None),
                        TranscriptionTask.updated_at < stale_threshold,
                    )
                )
                .values(
                    status="failed",  # Use string value
                    error_message="Task interrupted by server restart",
                    updated_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                )
            )

            result = await self.db.execute(stmt)
            await self.db.commit()

            if result.rowcount > 0:
                logger.warning(
                    f"Reset {result.rowcount} stale transcription tasks to FAILED (in-progress tasks that timed out)"
                )

            # 对于 PENDING 状态的任务，如果创建时间很久了但从未开始执行，也标记为失败
            # 这些任务可能是由于某些原因从未被调度执行
            pending_stale_threshold = datetime.now(timezone.utc) - timedelta(
                hours=1
            )  # 1小时
            stmt2 = (
                update(TranscriptionTask)
                .where(
                    and_(
                        TranscriptionTask.status == "pending",  # Use string value
                        TranscriptionTask.started_at.is_(None),  # 从未开始
                        TranscriptionTask.created_at
                        < pending_stale_threshold,  # 创建超过1小时
                    )
                )
                .values(
                    status="failed",  # Use string value
                    error_message="Task was never scheduled for execution",
                    updated_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                )
            )

            result2 = await self.db.execute(stmt2)
            await self.db.commit()

            if result2.rowcount > 0:
                logger.warning(
                    f"Reset {result2.rowcount} stale PENDING tasks to FAILED (never started)"
                )

        except Exception as e:
            logger.error(f"Failed to reset stale tasks: {str(e)}")

    async def cleanup_old_temp_files(self, days: int = 7):
        """
        清理旧的临时文件
        清理超过指定天数的失败或已取消任务的临时文件

        Args:
            days: 保留天数，默认7天
        """
        import os
        import shutil

        from sqlalchemy import and_

        from app.core.config import settings
        from app.domains.podcast.models import TranscriptionTask

        temp_dir = getattr(settings, "TRANSCRIPTION_TEMP_DIR", "./temp/transcription")
        temp_dir_abs = os.path.abspath(temp_dir)

        try:
            if not os.path.exists(temp_dir_abs):
                logger.info(
                    f"🧹 [CLEANUP] Temp directory does not exist: {temp_dir_abs}"
                )
                return {"cleaned": 0, "freed_bytes": 0}

            # 获取需要清理的episode_id列表
            # 条件：失败/已取消的任务，且超过指定天数
            stale_threshold = datetime.now(timezone.utc) - timedelta(days=days)
            stmt = (
                select(TranscriptionTask.episode_id)
                .where(
                    and_(
                        TranscriptionTask.status.in_(
                            ["failed", "cancelled"]
                        ),  # Use string values
                        TranscriptionTask.completed_at < stale_threshold,
                    )
                )
                .distinct()
            )

            result = await self.db.execute(stmt)
            episode_ids_to_cleanup = [row[0] for row in result.all()]

            cleaned_count = 0
            freed_bytes = 0

            for episode_id in episode_ids_to_cleanup:
                temp_episode_dir = os.path.join(temp_dir_abs, f"episode_{episode_id}")

                if os.path.exists(temp_episode_dir):
                    try:
                        # 计算目录大小
                        dir_size = sum(
                            os.path.getsize(os.path.join(dirpath, filename))
                            for dirpath, _, filenames in os.walk(temp_episode_dir)
                            for filename in filenames
                            if os.path.isfile(os.path.join(dirpath, filename))
                        )

                        # 删除目录
                        shutil.rmtree(temp_episode_dir)
                        cleaned_count += 1
                        freed_bytes += dir_size
                        logger.info(
                            f"🧹 [CLEANUP] Removed old temp directory for episode {episode_id}: {temp_episode_dir} ({dir_size / 1024 / 1024:.2f} MB)"
                        )

                    except Exception as e:
                        logger.error(
                            f"⚠️ [CLEANUP] Failed to remove temp directory for episode {episode_id}: {e}"
                        )

            logger.info(
                f"🧹 [CLEANUP] Summary: Cleaned {cleaned_count} old temp directories, freed {freed_bytes / 1024 / 1024:.2f} MB"
            )

            return {
                "cleaned": cleaned_count,
                "freed_bytes": freed_bytes,
                "freed_mb": round(freed_bytes / 1024 / 1024, 2),
            }

        except Exception as e:
            logger.error(f"❌ [CLEANUP] Failed to cleanup old temp files: {str(e)}")
            raise
