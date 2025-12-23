"""
播客AI摘要服务管理器
使用数据库中的AI模型配置
"""

import logging
from typing import Optional, Dict, Any
import time
import aiohttp
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.models import ModelType
from app.domains.podcast.models import TranscriptionTask, PodcastEpisode
from app.core.exceptions import ValidationError, HTTPException
from sqlalchemy import update

logger = logging.getLogger(__name__)


class SummaryModelManager:
    """摘要模型管理器"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_model_repo = AIModelConfigRepository(db)

    async def get_active_summary_model(self, model_name: Optional[str] = None):
        """获取活跃的文本生成模型配置"""
        if model_name:
            # 根据名称获取指定模型
            model = await self.ai_model_repo.get_by_name(model_name)
            if not model or not model.is_active or model.model_type != ModelType.TEXT_GENERATION:
                raise ValidationError(f"Summary model '{model_name}' not found or not active")
            return model
        else:
            # 获取默认文本生成模型
            model = await self.ai_model_repo.get_default_model(ModelType.TEXT_GENERATION)
            if not model:
                # 如果没有默认模型，获取第一个活跃模型
                active_models = await self.ai_model_repo.get_active_models(ModelType.TEXT_GENERATION)
                if not active_models:
                    raise ValidationError("No active summary model found")
                model = active_models[0]
            return model

    async def generate_summary(
        self,
        transcript: str,
        episode_info: Dict[str, Any],
        model_name: Optional[str] = None,
        custom_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """生成AI摘要"""
        model_config = await self.get_active_summary_model(model_name)

        # 解密API密钥
        api_key = await self._get_api_key(model_config)

        # 构建提示词
        if not custom_prompt:
            custom_prompt = self._build_default_prompt(episode_info, transcript)

        # 调用AI API生成摘要
        start_time = time.time()

        try:
            summary_content = await self._call_ai_api(
                model_config=model_config,
                api_key=api_key,
                prompt=custom_prompt,
                episode_info=episode_info
            )

            processing_time = time.time() - start_time

            # 更新使用统计
            await self.ai_model_repo.increment_usage(
                model_config.id,
                success=True,
                tokens_used=len(custom_prompt.split()) + len(summary_content.split())
            )

            return {
                "summary_content": summary_content,
                "model_name": model_config.name,
                "model_id": model_config.id,
                "processing_time": processing_time,
                "tokens_used": len(custom_prompt.split()) + len(summary_content.split())
            }

        except Exception as e:
            # 更新失败统计
            await self.ai_model_repo.increment_usage(
                model_config.id,
                success=False
            )
            raise

    async def _call_ai_api(
        self,
        model_config,
        api_key: str,
        prompt: str,
        episode_info: Dict[str, Any]
    ) -> str:
        """调用AI API生成摘要"""
        timeout = aiohttp.ClientTimeout(total=model_config.timeout_seconds)

        headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

        # 构建请求数据
        data = {
            'model': model_config.model_id,
            'messages': [
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            'max_tokens': model_config.max_tokens or 1000,
            'temperature': model_config.get_temperature_float() or 0.7
        }

        # 添加额外配置
        if model_config.extra_config:
            data.update(model_config.extra_config)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(f"{model_config.api_url}/chat/completions", headers=headers, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"AI API error: {response.status} - {error_text}")
                    raise HTTPException(
                        status_code=500,
                        detail=f"AI summary API error: {response.status}"
                    )

                result = await response.json()

                if 'choices' not in result or not result['choices']:
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid response from AI API"
                    )

                summary = result['choices'][0]['message']['content']
                return summary.strip()

    def _build_default_prompt(self, episode_info: Dict[str, Any], transcript: str) -> str:
        """构建默认的摘要提示词"""
        title = episode_info.get('title', '未知标题')
        description = episode_info.get('description', '')

        prompt = f"""
请为以下播客内容生成一个简洁但信息丰富的总结。

播客标题：{title}
播客描述：{description}

总结内容应该包括：
1. 主要话题和核心观点
2. 关键信息或要点
3. 适合的听众群体
4. 总结长度控制在200-500字之间

播客转录内容：
{transcript}
"""
        return prompt

    async def _get_api_key(self, model_config) -> str:
        """获取API密钥"""
        # 如果未加密，直接返回
        if not model_config.api_key_encrypted:
            return model_config.api_key if model_config.api_key else ""

        # 对于系统预设模型，从环境变量获取
        if model_config.is_system:
            from app.core.config import settings
            if model_config.provider == "openai":
                return getattr(settings, 'OPENAI_API_KEY', '')
            elif model_config.provider == "siliconflow":
                return getattr(settings, 'TRANSCRIPTION_API_KEY', '')

        # 对于用户自定义模型，使用Fernet解密
        from app.core.security import decrypt_data
        try:
            decrypted = decrypt_data(model_config.api_key)
            logger.info(f"Successfully decrypted API key for model {model_config.name}")
            return decrypted
        except Exception as e:
            logger.error(f"Failed to decrypt API key for model {model_config.name}: {e}")
            raise HTTPException(
                status_code=500,
                detail=f"Failed to decrypt API key for model {model_config.name}"
            )

    async def get_model_info(self, model_name: Optional[str] = None) -> Dict[str, Any]:
        """获取模型信息"""
        model_config = await self.get_active_summary_model(model_name)
        return {
            "model_id": model_config.id,
            "name": model_config.name,
            "display_name": model_config.display_name,
            "provider": model_config.provider,
            "model_id_str": model_config.model_id,
            "max_tokens": model_config.max_tokens,
            "temperature": model_config.temperature,
            "timeout_seconds": model_config.timeout_seconds,
            "extra_config": model_config.extra_config or {}
        }

    async def list_available_models(self):
        """列出所有可用的摘要模型"""
        active_models = await self.ai_model_repo.get_active_models(ModelType.TEXT_GENERATION)
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


class DatabaseBackedAISummaryService:
    """基于数据库配置的AI摘要服务"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.model_manager = SummaryModelManager(db)

    async def generate_summary(
        self,
        episode_id: int,
        model_name: Optional[str] = None,
        custom_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """为播客单集生成AI摘要"""
        # 获取播客单集信息
        from sqlalchemy import select
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if not episode:
            raise ValidationError(f"Episode {episode_id} not found")

        # 获取转录内容
        transcript_content = episode.transcript_content
        if not transcript_content:
            raise ValidationError(f"No transcript content available for episode {episode_id}")

        # 构建播客信息
        episode_info = {
            "title": episode.title,
            "description": episode.description,
            "duration": episode.audio_duration
        }

        # 生成摘要
        summary_result = await self.model_manager.generate_summary(
            transcript=transcript_content,
            episode_info=episode_info,
            model_name=model_name,
            custom_prompt=custom_prompt
        )

        # 更新数据库中的摘要信息
        await self._update_episode_summary(episode_id, summary_result)

        return summary_result

    async def _update_episode_summary(self, episode_id: int, summary_result: Dict[str, Any]):
        """更新播客单集的摘要信息"""
        from sqlalchemy import update

        # 更新播客单集表
        stmt = (
            update(PodcastEpisode)
            .where(PodcastEpisode.id == episode_id)
            .values(
                ai_summary=summary_result["summary_content"],
                summary_version="1.0",
                updated_at=datetime.utcnow()
            )
        )
        await self.db.execute(stmt)

        # 更新转录任务表（如果存在）
        from app.domains.podcast.models import TranscriptionTask
        stmt = (
            update(TranscriptionTask)
            .where(TranscriptionTask.episode_id == episode_id)
            .values(
                summary_content=summary_result["summary_content"],
                summary_model_used=summary_result["model_name"],
                summary_word_count=len(summary_result["summary_content"].split()),
                summary_processing_time=summary_result["processing_time"],
                summary_error_message=None,
                updated_at=datetime.utcnow()
            )
        )
        await self.db.execute(stmt)

        await self.db.commit()

    async def regenerate_summary(
        self,
        episode_id: int,
        model_name: Optional[str] = None,
        custom_prompt: Optional[str] = None
    ) -> Dict[str, Any]:
        """重新生成AI摘要"""
        return await self.generate_summary(episode_id, model_name, custom_prompt)

    async def get_summary_models(self):
        """获取可用的摘要模型列表"""
        return await self.model_manager.list_available_models()