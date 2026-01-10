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
        # 检查并处理过长的转录文本
        max_prompt_length = 100000  # 约 25k tokens
        if len(prompt) > max_prompt_length:
            logger.warning(f"Prompt too long ({len(prompt)} chars), truncating to {max_prompt_length} chars")
            prompt = prompt[:max_prompt_length] + "\n\n[内容过长，已截断]"

        # 构建 API URL - 避免路径重复
        api_url = model_config.api_url
        if not api_url.endswith('/chat/completions'):
            # 如果 URL 不包含完整路径，则添加
            if api_url.endswith('/'):
                api_url = f"{api_url}chat/completions"
            else:
                api_url = f"{api_url}/chat/completions"

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
            'temperature': model_config.get_temperature_float() or 0.7
        }

        # Only include max_tokens if it's set (some APIs don't accept null)
        if model_config.max_tokens is not None:
            data['max_tokens'] = model_config.max_tokens

        # 添加额外配置
        if model_config.extra_config:
            data.update(model_config.extra_config)

        # 详细日志记录
        logger.info(f"🤖 [AI API] Calling {model_config.provider} API:")
        logger.info(f"  - URL: {api_url}")
        logger.info(f"  - Model: {model_config.model_id}")
        logger.info(f"  - Prompt length: {len(prompt)} chars")
        logger.info(f"  - Max tokens: {model_config.max_tokens}")
        logger.info(f"  - Temperature: {data.get('temperature')}")

        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(api_url, headers=headers, json=data) as response:
                if response.status != 200:
                    error_text = await response.text()
                    logger.error(f"❌ [AI API] Request failed:")
                    logger.error(f"  - Status: {response.status}")
                    logger.error(f"  - Error: {error_text}")
                    logger.error(f"  - Request data keys: {list(data.keys())}")
                    logger.error(f"  - Headers: {headers}")

                    # 提供更具体的错误信息
                    if response.status == 400:
                        raise HTTPException(
                            status_code=500,
                            detail=f"AI API bad request (400). Possible causes: invalid model ID, malformed request, or prompt too long. Error: {error_text[:200]}"
                        )
                    elif response.status == 401:
                        raise HTTPException(
                            status_code=500,
                            detail=f"AI API authentication failed (401). Check API key configuration."
                        )
                    else:
                        raise HTTPException(
                            status_code=500,
                            detail=f"AI summary API error: {response.status} - {error_text[:200]}"
                        )

                result = await response.json()

                if 'choices' not in result or not result['choices']:
                    logger.error(f"❌ [AI API] Invalid response structure: {result}")
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid response from AI API"
                    )

                content = result['choices'][0].get('message', {}).get('content')
                if not content or not isinstance(content, str):
                    logger.error(f"❌ [AI API] Returned invalid content: {result}")
                    raise HTTPException(
                        status_code=500,
                        detail="AI API returned empty or invalid content"
                    )

                logger.info(f"✅ [AI API] Summary generated successfully: {len(content)} chars")
                return content.strip()

    def _build_default_prompt(self, episode_info: Dict[str, Any], transcript: str) -> str:
        """构建默认的摘要提示词"""
        title = episode_info.get('title', '未知标题')
        description = episode_info.get('description', '')

        prompt = f"""你是一位专业的播客内容分析师。请为以下播客内容生成一份详细且结构化的总结。

## 播客信息
**标题**：{title}
**描述**：{description}

## 转录内容
{transcript}

## 总结要求

【重要】你必须严格按照以下5个部分结构生成完整的总结，**不得遗漏任何部分**：

### 1. 主要话题概述
简要概括本期播客的核心主题（2-3句话）

### 2. 核心观点
列出本期播客表达的主要观点和见解（3-5个要点，每个要点用一句话概括）

### 3. 关键信息与要点
详细列出本期播客讨论的关键信息、数据、案例和重要细节：
- 重要数据或统计信息
- 具体案例或实例
- 人物、公司、事件等关键要素
- 时间、地点等背景信息
- 其他值得关注的细节

### 4. 讨论亮点
本期播客最有趣或最有价值的部分（1-2点）

### 5. 总结性陈述
用1-2句话总结本期播客的价值和意义

## 输出格式要求

1. **必须包含全部5个部分**，每个部分都要有明确的标题（### 1. 主要话题概述、### 2. 核心观点 等）
2. 每个部分都必须有实质内容，不能省略或跳过
3. 使用Markdown格式，确保结构清晰
4. 如果某个部分确实没有相关内容，请明确说明"本期播客未涉及此内容"，而不是直接省略该部分

## 质量标准
- 保持客观中立的立场
- 突出信息的准确性和完整性
- 使用清晰简洁的语言
- 确保总结的可读性和实用性
- 总结总长度建议在500-1500字之间

请开始生成完整的总结（确保包含所有5个部分）："""
        return prompt

    async def _get_api_key(self, model_config) -> str:
        """获取API密钥（统一从数据库读取，支持后备查找）"""
        # Placeholders that indicate invalid API keys
        invalid_api_keys = {
            'your-openai-api-key-here',
            'your-api-key-here',
            '',
            'none',
            'null',
            'your-ope************here',  # Partial match from error logs
        }

        def is_invalid_key(key: str) -> bool:
            """Check if API key is invalid/placeholder"""
            if not key:
                return True
            key_lower = key.lower().strip()
            # Check against known placeholders
            for placeholder in invalid_api_keys:
                if key_lower == placeholder.lower() or placeholder.lower() in key_lower:
                    return True
            # Check for common placeholder patterns
            if 'your-' in key_lower and ('key' in key_lower or 'api' in key_lower):
                return True
            return False

        # Helper to get and validate API key from a model
        async def get_valid_key_from_model(model) -> Optional[str]:
            if not model or not model.api_key:
                return None

            key = model.api_key
            if not model.api_key_encrypted:
                if is_invalid_key(key):
                    return None
                return key

            # Decrypt if encrypted
            from app.core.security import decrypt_data
            try:
                decrypted = decrypt_data(model.api_key)
                if is_invalid_key(decrypted):
                    return None
                return decrypted
            except Exception as e:
                logger.error(f"Failed to decrypt API key for model {model.name}: {e}")
                return None

        # First try to get API key from the provided model_config
        api_key = await get_valid_key_from_model(model_config)
        if api_key:
            logger.info(f"Using API key from model {model_config.name}")
            return api_key

        # If current model has invalid key, try to find another active model with valid key
        logger.warning(f"Model {model_config.name} has invalid or placeholder API key, searching for alternative...")

        active_models = await self.ai_model_repo.get_active_models(ModelType.TEXT_GENERATION)
        for model in active_models:
            if model.id == model_config.id:
                continue  # Skip the same model
            alt_key = await get_valid_key_from_model(model)
            if alt_key:
                logger.info(f"Found valid API key from alternative model: {model.name}")
                return alt_key

        # No valid API key found
        raise ValidationError(
            f"No valid API key found. Model '{model_config.name}' has a placeholder/invalid API key, "
            f"and no alternative models with valid API keys were found. "
            f"Please configure a valid API key for at least one TEXT_GENERATION model."
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
        import logging
        logger = logging.getLogger(__name__)
        from sqlalchemy import update

        try:
            # 获取总结内容和相关信息
            summary_content = summary_result["summary_content"]
            model_name = summary_result["model_name"]
            processing_time = summary_result["processing_time"]
            
            # 字段长度检查和处理
            max_summary_length = 100000  # 设置合理的最大长度限制
            original_length = len(summary_content)
            
            if original_length > max_summary_length:
                logger.warning(f"Summary content too long ({original_length} chars), truncating to {max_summary_length} chars")
                summary_content = summary_content[:max_summary_length] + "..."
            
            # 计算字数
            word_count = len(summary_content.split())
            
            logger.info(f"Updating summary for episode {episode_id}: {word_count} words, model: {model_name}")
            logger.debug(f"Summary content: {summary_content[:100]}...")

            # 更新播客单集表
            stmt = (
                update(PodcastEpisode)
                .where(PodcastEpisode.id == episode_id)
                .values(
                    ai_summary=summary_content,
                    summary_version="1.0",
                    updated_at=datetime.utcnow()
                )
            )
            logger.debug(f"Executing update on podcast_episodes table for episode {episode_id}")
            result = await self.db.execute(stmt)
            logger.debug(f"Update result on podcast_episodes: {result.rowcount} rows affected")

            # 更新转录任务表（如果存在）
            from app.domains.podcast.models import TranscriptionTask
            stmt = (
                update(TranscriptionTask)
                .where(TranscriptionTask.episode_id == episode_id)
                .values(
                    summary_content=summary_content,
                    summary_model_used=model_name,
                    summary_word_count=word_count,
                    summary_processing_time=processing_time,
                    summary_error_message=None,
                    updated_at=datetime.utcnow()
                )
            )
            logger.debug(f"Executing update on transcription_tasks table for episode {episode_id}")
            result = await self.db.execute(stmt)
            logger.debug(f"Update result on transcription_tasks: {result.rowcount} rows affected")

            logger.debug(f"Committing transaction for episode {episode_id}")
            await self.db.commit()
            logger.info(f"Successfully updated summary for episode {episode_id}")
            
        except Exception as e:
            logger.error(f"Failed to update summary for episode {episode_id}: {str(e)}")
            logger.exception("Exception details:")
            try:
                # 尝试回滚事务
                await self.db.rollback()
                logger.debug(f"Transaction rolled back for episode {episode_id}")
            except Exception as rollback_error:
                logger.error(f"Failed to rollback transaction for episode {episode_id}: {str(rollback_error)}")
            # 重新抛出异常，让上层处理
            raise

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