"""AI-powered text generation orchestration."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.utils import filter_thinking_content, sanitize_html
from app.domains.ai.repositories import AIModelConfigRepository


logger = logging.getLogger(__name__)


class TextGenerationService:
    """Generate AI-backed summaries and text outputs for application workflows."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AIModelConfigRepository(db)

    async def generate_podcast_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str = "transcript",
        max_tokens: int | None = None,
    ) -> str:
        from openai import (
            APIConnectionError,
            APIError,
            AsyncOpenAI,
            AuthenticationError,
            RateLimitError,
        )

        from app.core.security import decrypt_data
        from app.domains.ai.models import ModelType

        model_configs = await self.repo.get_active_models_by_priority(
            ModelType.TEXT_GENERATION,
        )
        if not model_configs:
            logger.warning(
                "No active text generation models configured, using rule-based summary",
            )
            return self._rule_based_summary(episode_title, content)

        last_error = None
        for idx, model_config in enumerate(model_configs):
            api_key = None
            try:
                if model_config.api_key:
                    api_key = (
                        decrypt_data(model_config.api_key)
                        if model_config.api_key_encrypted
                        else model_config.api_key
                    )

                if not api_key:
                    logger.warning(
                        "Model [%s] has empty API key, skipping",
                        model_config.display_name or model_config.name,
                    )
                    continue

                logger.info(
                    "Trying model [%s] (priority=%s, attempt %s/%s)",
                    model_config.display_name or model_config.name,
                    model_config.priority,
                    idx + 1,
                    len(model_configs),
                )

                client = AsyncOpenAI(
                    api_key=api_key,
                    base_url=model_config.api_url or None,
                )
                api_params = {
                    "model": model_config.model_id or "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": self._system_prompt()},
                        {
                            "role": "user",
                            "content": self._user_prompt(
                                episode_title=episode_title,
                                content=content,
                                content_type=content_type,
                            ),
                        },
                    ],
                    "temperature": 0.7,
                }
                if max_tokens is not None:
                    api_params["max_tokens"] = max_tokens

                response = await client.chat.completions.create(**api_params)
                raw_content = response.choices[0].message.content.strip()
                cleaned_content = filter_thinking_content(raw_content)
                safe_content = sanitize_html(cleaned_content)

                logger.info(
                    "Successfully generated summary using model [%s]",
                    model_config.display_name or model_config.name,
                )
                return safe_content
            except AuthenticationError as exc:
                last_error = exc
                logger.warning(
                    "Authentication failed for model %s: %s",
                    model_config.name,
                    exc,
                )
            except RateLimitError as exc:
                last_error = exc
                logger.warning(
                    "Rate limit exceeded for model %s: %s",
                    model_config.name,
                    exc,
                )
                continue
            except APIConnectionError as exc:
                last_error = exc
                logger.warning(
                    "Connection failed for model %s: %s",
                    model_config.name,
                    exc,
                )
            except APIError as exc:
                last_error = exc
                logger.warning(
                    "API error for model %s: %s",
                    model_config.name,
                    exc,
                )
            except Exception as exc:
                last_error = exc
                logger.error(
                    "Unexpected error with model %s: %s", model_config.name, exc
                )

        logger.error(
            "All AI models failed for summary generation. Last error: %s",
            last_error,
        )
        return self._rule_based_summary(episode_title, content)

    def _system_prompt(self) -> str:
        return """
你是一位专业的播客总结专家。你的任务是从播客单集内容中提取最有价值的信息。

请提取以下信息：
1. 主要话题和讨论点
2. 关键见解和结论
3. 可执行的建议
4. 需要进一步研究的领域

输出格式：
## 主要话题
[3-5个要点]

## 关键见解
[深入洞察]

## 行动建议
[具体步骤]

## 扩展思考
[关联问题]
"""

    def _user_prompt(
        self, *, episode_title: str, content: str, content_type: str
    ) -> str:
        return f"""
播客标题: {episode_title}
内容类型: {content_type}
内容: {content[:2000]}

请提供详细总结（150-300字）。
"""

    def _rule_based_summary(self, episode_title: str, content: str) -> str:
        sentences = content.split("。")
        summary_sentences = sentences[:3] if len(sentences) >= 3 else sentences
        summary = "。".join(summary_sentences).strip()

        if not summary:
            summary = f"《{episode_title}》的内容暂无总结。"

        return f"""
## 播客概览
节目名称: {episode_title}

## 内容摘要
{summary}

## 说明
此为系统自动生成的概要，完整总结正在处理中。
"""
