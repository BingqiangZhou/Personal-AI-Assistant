"""
播客AI摘要服务管理器
使用数据库中的AI模型配置
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Optional

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import HTTPException, ValidationError
from app.domains.ai.models import ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.podcast.models import PodcastEpisode
from app.domains.subscription.parsers.feed_parser import strip_html_tags


logger = logging.getLogger(__name__)


class SummaryModelManager:
    """摘要模型管理器"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_model_repo = AIModelConfigRepository(db)

    async def get_active_summary_model(self, model_name: Optional[str] = None):
        """获取活跃的文本生成模型配置（按优先级排序）"""
        if model_name:
            # 根据名称获取指定模型
            model = await self.ai_model_repo.get_by_name(model_name)
            if not model or not model.is_active or model.model_type != ModelType.TEXT_GENERATION:
                raise ValidationError(f"Summary model '{model_name}' not found or not active")
            return model
        else:
            # 按优先级获取文本生成模型列表
            active_models = await self.ai_model_repo.get_active_models_by_priority(ModelType.TEXT_GENERATION)
            if not active_models:
                raise ValidationError("No active summary model found")
            # 返回优先级最高的模型（priority 数字最小的）
            return active_models[0]

    async def generate_summary(
        self,
        transcript: str,
        episode_info: dict[str, Any],
        model_name: Optional[str] = None,
        custom_prompt: Optional[str] = None
    ) -> dict[str, Any]:
        """
        生成AI摘要（支持模型fallback机制）

        Args:
            transcript: 转录文本
            episode_info: 播客单集信息
            model_name: 指定的模型名称（可选）
            custom_prompt: 自定义提示词（可选）

        Returns:
            摘要结果字典

        Raises:
            ValidationError: 当所有模型都失败时抛出异常
        """
        # 获取按优先级排序的文本生成模型列表
        if model_name:
            # 如果指定了模型名称，只使用该模型
            model = await self.get_active_summary_model(model_name)
            models_to_try = [model]
        else:
            # 获取所有按优先级排序的活跃文本生成模型
            models_to_try = await self.ai_model_repo.get_active_models_by_priority(ModelType.TEXT_GENERATION)
            if not models_to_try:
                raise ValidationError("No active text generation models available")

        last_error = None
        total_processing_time = 0
        total_tokens_used = 0

        # 尝试每个模型（按优先级从高到低）
        for model_config in models_to_try:
            try:
                logger.info(f"Trying text generation model: {model_config.name} (priority: {model_config.priority})")

                # 解密API密钥
                api_key = await self._get_api_key(model_config)

                # 构建提示词
                if not custom_prompt:
                    custom_prompt = self._build_default_prompt(episode_info, transcript)

                # 调用AI API生成摘要（带重试）
                summary_content, processing_time, tokens_used = await self._call_ai_api_with_retry(
                    model_config=model_config,
                    api_key=api_key,
                    prompt=custom_prompt,
                    episode_info=episode_info
                )

                total_processing_time += processing_time
                total_tokens_used += tokens_used

                logger.info(f"Text generation succeeded with model: {model_config.name}")

                # 更新成功统计（只记录最后一次成功的调用，因为重试的失败已经在内部记录了）
                # 实际上重试的统计已经在 _call_ai_api_with_retry 中记录了，这里不需要重复记录

                return {
                    "summary_content": summary_content,
                    "model_name": model_config.name,
                    "model_id": model_config.id,
                    "processing_time": total_processing_time,
                    "tokens_used": total_tokens_used
                }

            except Exception as e:
                last_error = e
                logger.warning(f"Text generation failed with model {model_config.name}: {str(e)}")
                # 失败的统计已经在 _call_ai_api_with_retry 中记录了，这里不需要重复记录
                continue

        # 所有模型都失败了
        error_msg = f"All text generation models failed. Last error: {str(last_error)}"
        logger.error(error_msg)
        raise ValidationError(error_msg)

    async def _call_ai_api_with_retry(
        self,
        model_config,
        api_key: str,
        prompt: str,
        episode_info: dict[str, Any]
    ) -> tuple[str, float, int]:
        """
        调用AI API生成摘要（带重试机制）

        Args:
            model_config: 模型配置
            api_key: API密钥
            prompt: 提示词
            episode_info: 播客单集信息

        Returns:
            Tuple[摘要内容, 处理时间(秒), 使用的token数]

        Raises:
            Exception: 当所有重试都失败时抛出异常
        """
        max_retries = 3
        base_delay = 2  # seconds

        for attempt in range(max_retries):
            attempt_start = time.time()
            try:
                logger.info(f"📝 [SUMMARY] Attempt {attempt+1}/{max_retries} with model {model_config.name}")

                # 调用API
                summary_content = await self._call_ai_api(
                    model_config=model_config,
                    api_key=api_key,
                    prompt=prompt,
                    episode_info=episode_info
                )

                processing_time = time.time() - attempt_start
                tokens_used = len(prompt.split()) + len(summary_content.split())

                # 记录本次尝试成功
                await self.ai_model_repo.increment_usage(
                    model_config.id,
                    success=True,
                    tokens_used=tokens_used
                )
                logger.debug(f"📊 [STATS] Recorded success for model {model_config.name}, attempt {attempt+1}")

                return summary_content, processing_time, tokens_used

            except Exception as e:
                processing_time = time.time() - attempt_start
                logger.error(f"❌ [SUMMARY] Attempt {attempt+1} failed for model {model_config.name}: {str(e)}")

                # 记录本次尝试失败
                await self.ai_model_repo.increment_usage(
                    model_config.id,
                    success=False
                )
                logger.debug(f"📊 [STATS] Recorded failure for model {model_config.name}, attempt {attempt+1}")

                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    logger.info(f"⏳ [SUMMARY] Retrying in {delay}s...")
                    await asyncio.sleep(delay)
                else:
                    # 所有重试都失败了，抛出异常
                    raise Exception(f"Model {model_config.name} failed after {max_retries} attempts: {str(e)}")

        # 不应该到达这里
        raise Exception("Unexpected error in _call_ai_api_with_retry")

    async def _call_ai_api(
        self,
        model_config,
        api_key: str,
        prompt: str,
        episode_info: dict[str, Any]
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
                    logger.error("❌ [AI API] Request failed:")
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
                            detail="AI API authentication failed (401). Check API key configuration."
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

                # Filter out <thinking> tags and content
                # 过滤掉 <thinking> 标签及其内容
                from app.core.utils import filter_thinking_content
                original_length = len(content)
                cleaned_content = filter_thinking_content(content)

                if len(cleaned_content) != original_length:
                    logger.info(f"🧹 [FILTER] Removed thinking content: {original_length} -> {len(cleaned_content)} chars")

                logger.info(f"✅ [AI API] Summary generated successfully: {len(cleaned_content)} chars")
                return cleaned_content.strip()

    def _build_default_prompt(self, episode_info: dict[str, Any], transcript: str) -> str:
        """构建默认的摘要提示词"""
        title = episode_info.get('title', '未知标题')
        raw_description = episode_info.get('description', '')

        # 剥离HTML标签，确保AI只看到纯文本内容
        description = strip_html_tags(raw_description)

        prompt = f"""# Role
你是一位追求极致完整性的资深播客内容分析师。你的目标是将冗长的音频转录文本转化为一份详尽、结构化且**极易阅读**的深度研报。

# Task
请根据提供的元数据和转录文本生成总结。
**核心原则**：
1. **完整性**：内容完整性高于篇幅限制，不要受限于固定的段落数量。
2. **可读性**：**严禁使用大段落纯文本（Wall of Text）**。所有信息必须通过"标题 + 列表"的形式呈现，确保用户可以快速扫描核心信息。

# Input Data
<podcast_info>
Title: {title}
Shownotes: {description}
</podcast_info>

<transcript>
{transcript}
</transcript>

# Analysis Constraints
1. **全面覆盖**：不要遗漏任何一个主要话题。如果播客讨论了 10 个不同的话题，请生成 10 个对应的小节。
2. **事实来源严格分级**：
    - **最高优先级**：<transcript>。所有的观点、数据、结论必须严格源自实际的对话转录。
    - **辅助参考**：<podcast_info> (Shownotes)。仅用于提取正确的人名拼写、专业术语。
    - **冲突处理**：如果 Shownotes 内容在 Transcript 中未出现，**坚决不写入总结**。
3. **视觉层级**：这是为了解决"阅读不便"的问题。
    - **多用列表**：主要内容必须使用无序列表（- ）或有序列表（1. ）呈现。
    - **加粗关键**：对人名、工具名、核心数据、关键结论进行**加粗**处理。

# Output Structure (Strictly Follow)

## 1. 一句话摘要 (Executive Summary)
用精炼的语言（50-100字）概括整期播客的核心主旨。

## 2. 核心观点与洞察 (Key Insights & Takeaways)
提取本期播客中所有具有独立价值的观点。
- **数量不限**：务必覆盖所有关键结论。
- **格式要求**：使用列表形式。
    - **[观点关键词]**：详细阐述。
- **逻辑分组**：如果观点较多，请使用**三级标题（###）**进行分类（例如：### 市场趋势、### 技术实现），每一类下面再列出具体观点。

## 3. 内容深度拆解 (Deep Dive / Topic Breakdown)
**这是本总结最核心的部分。** 请顺着对话的时间线或逻辑流，将长文本自然拆解为多个板块。

**【重要格式要求】**：在此部分，**禁止使用自然段落写作**。必须使用**"小标题 + 嵌套列表"**的结构。

- **切分原则**：每当对话切换到一个新的重大话题或议程时，就创建一个新的**三级标题**（例如：### 3.1 话题：...）。
- **内容呈现方式**：
    - 使用 **无序列表** 罗列该话题下的核心论点。
    - 在论点之下，使用 **缩进列表** 补充具体的论据、数据、案例或正反方观点。
    - **人名/工具/数据**：必须**加粗**显示。
    - **示例结构**：
        * **核心论点 A**
            * 细节解释：...
            * 提到的案例：**某某公司**的例子...
        * **核心论点 B**
            * 嘉宾 **[名字]** 提出的反对意见：...
            * 相关数据：增长了 **40%**...

## 4. 精彩语录与金句 (Memorable Quotes)
摘录原文中所有打动人心、发人深省或具有幽默感的原话。
- **格式要求**：使用列表形式。
- **要求**：注明说话人（如果有）和简短背景。

## 5. 适合听众与收获 (Audience & Value)
简要说明本期内容适合哪类人群深入聆听，以及他们能从中学到什么。

# Start Analysis
请开始进行详尽的分析，确保所有内容"条理化"、"列表化"，严格遵守事实分级原则：
"""
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
            # Check against known placeholders (skip empty strings to avoid false positives)
            for placeholder in invalid_api_keys:
                if not placeholder:
                    continue  # Skip empty placeholders
                placeholder_lower = placeholder.lower()
                if key_lower == placeholder_lower or placeholder_lower in key_lower:
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

    async def get_model_info(self, model_name: Optional[str] = None) -> dict[str, Any]:
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
    ) -> dict[str, Any]:
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

    async def _update_episode_summary(self, episode_id: int, summary_result: dict[str, Any]):
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
    ) -> dict[str, Any]:
        """重新生成AI摘要"""
        return await self.generate_summary(episode_id, model_name, custom_prompt)

    async def get_summary_models(self):
        """获取可用的摘要模型列表"""
        return await self.model_manager.list_available_models()
