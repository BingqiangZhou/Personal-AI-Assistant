"""
播客转录服务管理器
使用数据库中的AI模型配置
"""

import logging
from typing import Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.models import ModelType
from app.domains.podcast.transcription import (
    SiliconFlowTranscriber,
    AudioDownloader,
    AudioConverter,
    AudioSplitter,
    PodcastTranscriptionService
)
from app.core.exceptions import ValidationError
from app.core.database import async_session_factory

logger = logging.getLogger(__name__)


class TranscriptionModelManager:
    """转录模型管理器"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_model_repo = AIModelConfigRepository(db)

    async def get_active_transcription_model(self, model_name: Optional[str] = None):
        """获取活跃的转录模型配置"""
        if model_name:
            # 根据名称获取指定模型
            model = await self.ai_model_repo.get_by_name(model_name)
            if not model or not model.is_active or model.model_type != ModelType.TRANSCRIPTION:
                raise ValidationError(f"Transcription model '{model_name}' not found or not active")
            return model
        else:
            # 获取默认转录模型
            model = await self.ai_model_repo.get_default_model(ModelType.TRANSCRIPTION)
            if not model:
                # 如果没有默认模型，获取第一个活跃模型
                active_models = await self.ai_model_repo.get_active_models(ModelType.TRANSCRIPTION)
                if not active_models:
                    raise ValidationError("No active transcription model found")
                model = active_models[0]
            return model

    async def create_transcriber(self, model_name: Optional[str] = None):
        """创建转录器实例"""
        model_config = await self.get_active_transcription_model(model_name)

        # 解密API密钥
        api_key = await self._get_api_key(model_config)

        # 根据提供商创建对应的转录器
        if model_config.provider == "siliconflow":
            return SiliconFlowTranscriber(
                api_key=api_key,
                api_url=model_config.api_url,
                max_concurrent=model_config.max_concurrent_requests
            )
        elif model_config.provider == "openai":
            # OpenAI的转录服务API格式类似，可以使用相同的转录器
            return SiliconFlowTranscriber(
                api_key=api_key,
                api_url=model_config.api_url,
                max_concurrent=model_config.max_concurrent_requests
            )
        else:
            # 自定义提供商，尝试使用通用转录器
            return SiliconFlowTranscriber(
                api_key=api_key,
                api_url=model_config.api_url,
                max_concurrent=model_config.max_concurrent_requests
            )

    async def get_model_info(self, model_name: Optional[str] = None) -> Dict[str, Any]:
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
            "extra_config": model_config.extra_config or {}
        }

    async def list_available_models(self):
        """列出所有可用的转录模型"""
        active_models = await self.ai_model_repo.get_active_models(ModelType.TRANSCRIPTION)
        return [
            {
                "id": model.id,
                "name": model.name,
                "display_name": model.display_name,
                "provider": model.provider,
                "model_id": model.model_id,
                "is_default": model.is_default
            }
            for model in active_models
        ]

    async def _get_api_key(self, model_config) -> str:
        """获取API密钥"""
        # 对于系统预设模型，从环境变量获取
        if model_config.is_system:
            from app.core.config import settings
            if model_config.provider == "openai":
                return getattr(settings, 'OPENAI_API_KEY', '')
            elif model_config.provider == "siliconflow":
                return getattr(settings, 'TRANSCRIPTION_API_KEY', '')

        # 对于用户自定义的模型，这里应该从安全存储解密
        # 暂时直接返回（实际应该解密）
        return model_config.api_key if model_config.api_key else ""


class DatabaseBackedTranscriptionService(PodcastTranscriptionService):
    """基于数据库配置的转录服务"""

    def __init__(self, db: AsyncSession):
        super().__init__(db)
        self.model_manager = TranscriptionModelManager(db)

    async def start_transcription(
        self,
        episode_id: int,
        model_name: Optional[str] = None,
        force: bool = False
    ):
        """启动转录任务，支持指定模型和强制模式"""
        # 获取模型信息
        model_info = await self.model_manager.get_model_info(model_name)

        # 调用父类方法，传递模型名称和force参数
        return await super().start_transcription(episode_id, model_name, force)

    async def _execute_transcription(self, task_id: int, config_db_id: Optional[int] = None):
        """执行转录任务（后台运行），使用数据库中的模型配置"""
        logger.info(f"manager._execute_transcription: Starting background transcription execution for task {task_id}")
        # Add a diagnostic log to see if we're hitting the session factory
        logger.info(f"manager._execute_transcription: Attempting to create session for task {task_id}")
        async with async_session_factory() as session:
            try:
                logger.info(f"manager._execute_transcription: Retrieving task {task_id} from database")
                # 获取任务信息
                from app.domains.podcast.models import TranscriptionTask
                stmt = select(TranscriptionTask).where(TranscriptionTask.id == task_id)
                result = await session.execute(stmt)
                task = result.scalar_one_or_none()

                if not task:
                    logger.error(f"manager._execute_transcription: Transcription task {task_id} not found")
                    return

                logger.info(f"manager._execute_transcription: Task {task_id} found, checking extra_config")
                # 从任务的extra_config中获取指定的模型名称（如果有）
                model_name = None
                if task.extra_config and isinstance(task.extra_config, dict):
                    model_name = task.extra_config.get('model_name')

                logger.info(f"manager._execute_transcription: Creating transcriber for model: {model_name}")
                # 创建转录器
                transcriber = await self.model_manager.create_transcriber(model_name)

                logger.info("manager._execute_transcription: Transcriber created successfully, updating usage stats")
                # 更新模型使用统计
                model_config = await self.model_manager.get_active_transcription_model(model_name)
                logger.info(f"manager._execute_transcription: Using model config: {model_config.model_id} (Provider: {model_config.provider})")
                
                await self.model_manager.ai_model_repo.increment_usage(
                    model_config.id,
                    success=True
                )

                # 继续执行原有的转录逻辑
                # Note: The parent's _execute_transcription will use its own session
                # We need to call it directly since it already handles session management
                logger.info(f"manager._execute_transcription: Calling parent _execute_transcription for task {task_id}")
                await super()._execute_transcription(task_id, config_db_id)
                logger.info(f"manager._execute_transcription: Parent _execute_transcription completed for task {task_id}")

            except Exception as e:
                import traceback
                error_trace = traceback.format_exc()
                logger.error(f"manager._execute_transcription: Transcription failed for task {task_id}: {str(e)}\nTraceback: {error_trace}")

                # 更新失败统计
                try:
                    model_name = None
                    if 'task' in locals() and task.extra_config and isinstance(task.extra_config, dict):
                        model_name = task.extra_config.get('model_name')

                    model_config = await self.model_manager.get_active_transcription_model(model_name)
                    await self.model_manager.ai_model_repo.increment_usage(
                        model_config.id,
                        success=False
                    )
                except:
                    pass  # 忽略统计更新错误

                # 调用父类的错误处理
                await super()._execute_transcription(task_id, config_db_id)

    async def get_transcription_models(self):
        """获取可用的转录模型列表"""
        return await self.model_manager.list_available_models()

    async def reset_stale_tasks(self):
        """
        重置所有处于中间状态的任务为失败
        用于服务器重启后清理僵尸任务
        """
        from app.domains.podcast.models import TranscriptionTask, TranscriptionStatus
        from sqlalchemy import update
        
        stale_statuses = [
            TranscriptionStatus.PENDING,
            TranscriptionStatus.DOWNLOADING,
            TranscriptionStatus.CONVERTING,
            TranscriptionStatus.SPLITTING,
            TranscriptionStatus.TRANSCRIBING,
            TranscriptionStatus.MERGING
        ]
        
        try:
            stmt = (
                update(TranscriptionTask)
                .where(TranscriptionTask.status.in_(stale_statuses))
                .values(
                    status=TranscriptionStatus.FAILED,
                    error_message="Task interrupted by server restart",
                    updated_at=datetime.utcnow(),
                    completed_at=datetime.utcnow()
                )
            )
            
            result = await self.db.execute(stmt)
            await self.db.commit()
            
            if result.rowcount > 0:
                logger.warning(f"Reset {result.rowcount} stale transcription tasks to FAILED")
        except Exception as e:
            logger.error(f"Failed to reset stale tasks: {str(e)}")