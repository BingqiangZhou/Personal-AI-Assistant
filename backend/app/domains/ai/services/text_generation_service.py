"""AI-powered text generation orchestration."""

from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.ai_client import AIClientService
from app.domains.ai.models import ModelType
from app.domains.ai.repositories import AIModelConfigRepository
from app.domains.ai.services.model_security_service import AIModelSecurityService


logger = logging.getLogger(__name__)


class TextGenerationService:
    """Generate AI-backed summaries and text outputs for application workflows."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo = AIModelConfigRepository(db)
        self.security_service = AIModelSecurityService(db)

    async def generate_podcast_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str = "transcript",
        max_tokens: int | None = None,
    ) -> str:

        model_configs = await self.repo.get_active_models_by_priority(
            ModelType.TEXT_GENERATION,
        )
        if not model_configs:
            logger.warning(
                "No active text generation models configured, using rule-based summary",
            )
            return self._rule_based_summary(episode_title, content)

        messages = [
            {"role": "system", "content": self._system_prompt()},
            {
                "role": "user",
                "content": self._user_prompt(
                    episode_title=episode_title,
                    content=content,
                    content_type=content_type,
                ),
            },
        ]

        async def fallback() -> str:
            return self._rule_based_summary(episode_title, content)

        ai_client = AIClientService(
            repo=self.repo,
            security_service=self.security_service,
        )

        result, _model = await ai_client.call_with_fallback(
            messages,
            model_type=ModelType.TEXT_GENERATION,
            max_tokens=max_tokens,
            temperature=0.7,
            operation_name="Podcast summary generation",
            fallback_handler=fallback,
        )
        return result

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
