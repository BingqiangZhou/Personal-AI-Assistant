"""
播客对话交互服务
支持基于AI摘要的上下文保持对话
"""

import logging
from typing import Optional, List, Dict, Any
import time
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload

from app.domains.podcast.models import PodcastEpisode, PodcastConversation
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.models import ModelType
from app.core.exceptions import ValidationError

logger = logging.getLogger(__name__)


class ConversationService:
    """播客对话服务"""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.ai_model_repo = AIModelConfigRepository(db)

    async def get_conversation_history(
        self,
        episode_id: int,
        user_id: int,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """获取对话历史"""
        stmt = (
            select(PodcastConversation)
            .where(
                and_(
                    PodcastConversation.episode_id == episode_id,
                    PodcastConversation.user_id == user_id
                )
            )
            .order_by(PodcastConversation.conversation_turn, PodcastConversation.created_at)
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        conversations = result.scalars().all()

        return [
            {
                "id": conv.id,
                "role": conv.role,
                "content": conv.content,
                "conversation_turn": conv.conversation_turn,
                "created_at": conv.created_at.isoformat()
            }
            for conv in conversations
        ]

    async def send_message(
        self,
        episode_id: int,
        user_id: int,
        user_message: str,
        model_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """发送消息并获取AI回复"""
        # 获取播客单集信息
        stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode_id)
        result = await self.db.execute(stmt)
        episode = result.scalar_one_or_none()

        if not episode:
            raise ValidationError(f"Episode {episode_id} not found")

        if not episode.ai_summary:
            raise ValidationError("Cannot start conversation: AI summary not available for this episode")

        # 获取对话历史
        conversation_history = await self.get_conversation_history(episode_id, user_id)

        # 确定当前对话轮次
        current_turn = len(conversation_history)

        # 保存用户消息
        user_conv = PodcastConversation(
            episode_id=episode_id,
            user_id=user_id,
            role="user",
            content=user_message,
            conversation_turn=current_turn,
            created_at=datetime.utcnow()
        )
        self.db.add(user_conv)
        await self.db.flush()  # 获取ID

        # 构建对话上下文
        messages = self._build_conversation_context(episode, conversation_history, user_message)

        # 调用AI API
        start_time = time.time()
        ai_response_content = await self._call_ai_api(messages, model_name)
        processing_time = time.time() - start_time

        # 保存AI回复
        assistant_conv = PodcastConversation(
            episode_id=episode_id,
            user_id=user_id,
            role="assistant",
            content=ai_response_content,
            parent_message_id=user_conv.id,
            conversation_turn=current_turn + 1,
            processing_time=processing_time,
            created_at=datetime.utcnow()
        )
        self.db.add(assistant_conv)

        await self.db.commit()
        await self.db.refresh(assistant_conv)

        logger.info(f"Conversation saved for episode {episode_id}, user {user_id}, turn {current_turn + 1}")

        return {
            "id": assistant_conv.id,
            "role": "assistant",
            "content": assistant_conv.content,
            "conversation_turn": assistant_conv.conversation_turn,
            "processing_time": processing_time,
            "created_at": assistant_conv.created_at.isoformat()
        }

    def _build_conversation_context(
        self,
        episode: PodcastEpisode,
        conversation_history: List[Dict[str, Any]],
        user_message: str
    ) -> List[Dict[str, str]]:
        """构建对话上下文"""
        messages = []

        # 系统提示词 - 包含AI摘要作为上下文
        system_prompt = f"""你是一位专业的播客内容分析师和讨论伙伴。用户正在与你讨论一期播客节目的AI总结。

## 播客信息
**标题**: {episode.title}
**描述**: {episode.description or '无'}

## AI总结内容
{episode.ai_summary}

## 对话规则
1. 基于上面的AI总结内容回答用户问题
2. 如果用户询问总结中未涵盖的细节，请诚实地说明总结中未包含该信息
3. 保持回答的准确性和客观性
4. 可以根据总结内容进行合理的推理和分析
5. 回答要简洁明了，直接回应用户的问题
6. 如果需要，可以引用总结中的具体内容
"""

        messages.append({"role": "system", "content": system_prompt})

        # 添加历史对话
        for conv in conversation_history:
            messages.append({
                "role": conv["role"],
                "content": conv["content"]
            })

        # 添加当前用户消息
        messages.append({
            "role": "user",
            "content": user_message
        })

        return messages

    async def _call_ai_api(
        self,
        messages: List[Dict[str, str]],
        model_name: Optional[str] = None
    ) -> str:
        """
        调用AI API进行对话
        按优先级获取模型配置，实现fallback机制
        """
        import aiohttp

        # 获取活跃的文本生成模型
        if model_name:
            model = await self.ai_model_repo.get_by_name(model_name)
            if not model or not model.is_active or model.model_type != ModelType.TEXT_GENERATION:
                raise ValidationError(f"Chat model '{model_name}' not found or not active")
            models_to_try = [model]
        else:
            # 按优先级获取所有活跃的文本生成模型
            models_to_try = await self.ai_model_repo.get_active_models_by_priority(ModelType.TEXT_GENERATION)
            if not models_to_try:
                raise ValidationError("No active chat model found")

        # 按 priority 依次尝试每个模型
        last_error = None
        for idx, model in enumerate(models_to_try):
            try:
                logger.info(f"尝试使用对话模型 [{model.display_name or model.name}] (priority={model.priority}, 尝试 {idx + 1}/{len(models_to_try)})")

                # 解密API密钥
                api_key = await self._get_api_key(model)
                if not api_key:
                    logger.warning(f"模型配置 [{model.display_name or model.name}] (priority={model.priority}) 的 API key 为空，跳过")
                    continue

                # 构建请求数据
                data = {
                    'model': model.model_id,
                    'messages': messages,
                    'max_tokens': model.max_tokens or 1500,
                    'temperature': model.get_temperature_float() or 0.7
                }

                # 添加额外配置
                if model.extra_config:
                    data.update(model.extra_config)

                timeout = aiohttp.ClientTimeout(total=model.timeout_seconds)

                headers = {
                    'Authorization': f'Bearer {api_key}',
                    'Content-Type': 'application/json'
                }

                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.post(f"{model.api_url}/chat/completions", headers=headers, json=data) as response:
                        if response.status != 200:
                            error_text = await response.text()
                            last_error = f"HTTP {response.status}: {error_text}"
                            logger.error(f"模型配置 [{model.display_name or model.name}] (priority={model.priority}) API 错误: {last_error}")
                            continue

                        result = await response.json()

                        if 'choices' not in result or not result['choices']:
                            last_error = "Invalid response from AI API"
                            logger.error(f"模型配置 [{model.display_name or model.name}] (priority={model.priority}) {last_error}")
                            continue

                        content = result['choices'][0]['message']['content']
                        logger.info(f"成功使用对话模型 [{model.display_name or model.name}] (priority={model.priority})")
                        return content.strip()

            except aiohttp.ClientTimeout as e:
                last_error = e
                logger.error(f"模型配置 [{model.display_name or model.name}] (priority={model.priority}) 请求超时: {e}")
            except aiohttp.ClientError as e:
                last_error = e
                logger.error(f"模型配置 [{model.display_name or model.name}] (priority={model.priority}) 网络错误: {e}")
            except Exception as e:
                last_error = e
                logger.error(f"模型配置 [{model.display_name or model.name}] (priority={model.priority}) 未知错误: {type(e).__name__}: {e}")

        # 所有模型都失败了
        error_msg = f"所有 {len(models_to_try)} 个对话模型配置均访问失败，最后错误: {type(last_error).__name__}: {last_error}"
        logger.error(error_msg)
        raise ValidationError(error_msg)

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
            raise ValidationError(f"Failed to decrypt API key for model {model_config.name}")

    async def clear_conversation_history(
        self,
        episode_id: int,
        user_id: int
    ) -> int:
        """清除对话历史"""
        stmt = (
            select(PodcastConversation)
            .where(
                and_(
                    PodcastConversation.episode_id == episode_id,
                    PodcastConversation.user_id == user_id
                )
            )
        )
        result = await self.db.execute(stmt)
        conversations = result.scalars().all()

        count = len(conversations)
        for conv in conversations:
            await self.db.delete(conv)

        await self.db.commit()
        logger.info(f"Cleared {count} conversation messages for episode {episode_id}, user {user_id}")

        return count
