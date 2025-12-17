"""
播客业务逻辑服务 - Podcast Services

核心服务:
1. PodcastController: 管理播客订阅和单集
2. PodcastSummaryService: AI总结生成
3. PodcastSyncService: RSS轮询和同步
"""

import logging
from typing import List, Tuple, Optional
from datetime import datetime, timedelta
import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.llm_privacy import ContentSanitizer
from app.core.redis import PodcastRedis
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.models import PodcastEpisode
from app.domains.subscription.models import Subscription
from app.domains.assistant.models import Conversation, Message
from app.integration.podcast.security import PodcastSecurityValidator
from app.integration.podcast.secure_rss_parser import SecureRSSParser, PodcastFeed

logger = logging.getLogger(__name__)


class PodcastService:
    """
    播客核心服务 - 统一接口
    """

    def __init__(self, db: AsyncSession, user_id: int):
        self.db = db
        self.user_id = user_id
        self.repo = PodcastRepository(db)
        self.redis = PodcastRedis()
        self.sanitizer = ContentSanitizer(mode=settings.LLM_CONTENT_SANITIZE_MODE)
        self.security = PodcastSecurityValidator()
        self.parser = SecureRSSParser(user_id)

    # === 订阅管理 ===

    async def add_subscription(
        self,
        feed_url: str,
        custom_name: Optional[str] = None
    ) -> Tuple[Subscription, List[PodcastEpisode]]:
        """
        添加播客订阅
        返回: (subscription, new_episodes)
        """
        # 1. 验证并解析RSS
        success, feed, error = await self.parser.fetch_and_parse_feed(feed_url)
        if not success:
            raise ValueError(f"无法解析播客: {error}")

        # 2. 检查订阅数量限制
        existing_subs = await self.repo.get_user_subscriptions(self.user_id)
        if len(existing_subs) >= settings.MAX_PODCAST_SUBSCRIPTIONS:
            raise ValueError(f"已达到最大订阅数量: {settings.MAX_PODCAST_SUBSCRIPTIONS}")

        # 3. 创建或更新订阅
        subscription = await self.repo.create_or_update_subscription(
            self.user_id,
            feed_url,
            feed.title,
            feed.description,
            custom_name
        )

        # 4. 保存并总结新单集
        new_episodes = []
        for episode in feed.episodes[:10]:  # 前10个
            saved_episode, is_new = await self.repo.create_or_update_episode(
                subscription_id=subscription.id,
                guid=episode.guid or f"{feed_url}-{episode.title}",
                title=episode.title,
                description=episode.description,
                audio_url=episode.audio_url,
                published_at=episode.published_at,
                audio_duration=episode.duration,
                transcript_url=episode.transcript_url,
                metadata={"feed_title": feed.title}
            )

            if is_new:
                new_episodes.append(saved_episode)
                # 异步触发AI总结
                asyncio.create_task(self._generate_summary_task(saved_episode))

        logger.info(f"用户{self.user_id} 添加播客: {feed.title}, {len(new_episodes)}新模式")
        return subscription, new_episodes

    async def list_subscriptions(self) -> List[dict]:
        """列出用户的所有播客订阅"""
        subscriptions = await self.repo.get_user_subscriptions(self.user_id)

        results = []
        for sub in subscriptions:
            # 获取最新3个单集
            episodes = await self.repo.get_subscription_episodes(sub.id, limit=3)

            results.append({
                "id": sub.id,
                "title": sub.title,
                "description": sub.description,
                "feed_url": sub.source_url,
                "episode_count": await self._get_episode_count(sub.id),
                "latest_episodes": [{
                    "id": ep.id,
                    "title": ep.title,
                    "published_at": ep.published_at,
                    "has_summary": ep.ai_summary is not None
                } for ep in episodes],
                "status": sub.status,
                "created_at": sub.created_at
            })

        return results

    async def get_subscription_details(self, subscription_id: int) -> Optional[dict]:
        """获取订阅详情及单集列表"""
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        if not sub:
            return None

        episodes = await self.repo.get_subscription_episodes(subscription_id, limit=50)
        pending_count = len([e for e in episodes if not e.ai_summary])

        return {
            "id": sub.id,
            "title": sub.title,
            "description": sub.description,
            "episode_count": len(episodes),
            "pending_summaries": pending_count,
            "episodes": [{
                "id": ep.id,
                "title": ep.title,
                "description": ep.description[:100] + "..." if len(ep.description) > 100 else ep.description,
                "audio_url": ep.audio_url,
                "duration": ep.audio_duration,
                "published_at": ep.published_at,
                "has_summary": ep.ai_summary is not None,
                "summary": ep.ai_summary[:200] + "..." if ep.ai_summary and len(ep.ai_summary) > 200 else ep.ai_summary,
                "ai_confidence": ep.ai_confidence_score,
                "play_count": ep.play_count
            } for ep in episodes]
        }

    async def remove_subscription(self, subscription_id: int) -> bool:
        """删除订阅"""
        sub = await self.repo.get_subscription_by_id(self.user_id, subscription_id)
        if not sub:
            return False

        await self.db.delete(sub)
        await self.db.commit()
        logger.info(f"用户{self.user_id} 删除订阅: {sub.title}")
        return True

    # === 单集管理与AI总结 ===

    async def get_episode_with_summary(self, episode_id: int) -> Optional[dict]:
        """获取单集详情和AI总结"""
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            return None

        # 检查是否有待处理的总结
        if not episode.ai_summary and episode.status == "pending_summary":
            # 触发后台总结
            asyncio.create_task(self._generate_summary_task(episode))

        playback = await self.repo.get_playback_state(self.user_id, episode_id)

        return {
            "id": episode.id,
            "title": episode.title,
            "description": episode.description,
            "audio_url": episode.audio_url,
            "duration": episode.audio_duration,
            "published_at": episode.published_at,
            "transcript": episode.transcript_content,
            "summary": episode.ai_summary,
            "summary_status": episode.status,
            "ai_confidence": episode.ai_confidence_score,
            "playback": {
                "progress": playback.current_position if playback else 0,
                "is_playing": playback.is_playing if playback else False,
                "play_count": episode.play_count
            } if playback else None
        }

    async def generate_summary_for_episode(self, episode_id: int) -> str:
        """
        为指定单集生成AI总结（同步方式，用于明确需要等待的场景）
        """
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        if episode.ai_summary:
            return episode.ai_summary

        return await self._generate_summary(episode)

    async def regenerate_summary(self, episode_id: int, force: bool = False) -> str:
        """
        重新生成总结
        force: 即使已有总结也重新生成
        """
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        if episode.ai_summary and not force:
            return episode.ai_summary

        return await self._generate_summary(episode, version="v2")

    async def get_pending_summaries(self) -> List[dict]:
        """获取待总结的单集"""
        subscriptions = await self.repo.get_user_subscriptions(self.user_id)
        results = []

        for sub in subscriptions:
            pending = await self.repo.get_unsummarized_episodes(sub.id)
            for episode in pending:
                results.append({
                    "episode_id": episode.id,
                    "subscription_title": sub.title,
                    "episode_title": episode.title,
                    "size_estimate": len(episode.description) + (len(episode.transcript_content) or 0)
                })

        return results

    # === 播放与进度管理 ===

    async def update_playback_progress(
        self,
        episode_id: int,
        progress_seconds: int,
        is_playing: bool = False
    ) -> dict:
        """更新播放进度"""
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        playback = await self.repo.update_playback_progress(
            self.user_id,
            episode_id,
            progress_seconds,
            is_playing
        )

        return {
            "episode_id": episode_id,
            "progress": playback.current_position,
            "is_playing": playback.is_playing,
            "play_count": playback.play_count
        }

    # === 私有辅助方法 ===

    async def _generate_summary_task(self, episode: PodcastEpisode):
        """后台任务：异步生成AI总结"""
        try:
            if not episode.ai_summary:
                await self._generate_summary(episode)
        except Exception as e:
            logger.error(f"异步总结失败 episode:{episode.id}: {e}")
            await self.repo.mark_summary_failed(episode.id, str(e))

    async def _generate_summary(self, episode: PodcastEpisode, version: str = "v1") -> str:
        """核心AI总结生成逻辑"""
        # 检查锁，防止重复处理
        lock_key = f"summary:{episode.id}"
        if not await self.redis.acquire_lock(lock_key, expire=300):
            logger.info(f"已有人在处理 episode:{episode.id}")
            # 等待
            current_try = 0
            while current_try < 5:
                await asyncio.sleep(2)
                episode = await self.repo.get_episode_by_id(episode.id)  # Refresh
                if episode and episode.ai_summary:
                    return episode.ai_summary
                current_try += 1

        try:
            # 准备内容（优先使用转录文本）
            if episode.transcript_content:
                raw_content = episode.transcript_content
                content_type = "transcript"
                has_transcript = True
            else:
                raw_content = episode.description
                content_type = "description"
                has_transcript = False

            # 使用隐私净化器加工内容
            sanitized_prompt = self.sanitizer.sanitize(
                raw_content, self.user_id, f"podcast_{content_type}"
            )

            if not sanitized_prompt or len(sanitized_prompt.strip()) < 10:
                raise ValueError("内容太短或已被完全过滤")

            # 调用AI生成总结
            summary = await self._call_llm_for_summary(
                episode_title=episode.title,
                content=sanitized_prompt,
                content_type=content_type
            )

            # 保存到数据库和缓存
            await self.repo.update_ai_summary(
                episode.id,
                summary,
                version=version,
                transcript_used=has_transcript
            )

            logger.info(f"AI总结完成 episode:{episode.id} ({content_type})")
            return summary

        except Exception as e:
            logger.error(f"生成AI总结失败 episode:{episode.id}: {e}")
            await self.repo.mark_summary_failed(episode.id, str(e))
            raise
        finally:
            await self.redis.release_lock(lock_key)

    async def _call_llm_for_summary(
        self,
        episode_title: str,
        content: str,
        content_type: str
    ) -> str:
        """
        调用LLM API生成总结
        这里假设使用OpenAI格式，可替换为其他LLM
        """
        from openai import AsyncOpenAI

        if not settings.OPENAI_API_KEY:
            # 降级到规则生成（测试环境）
            return self._rule_based_summary(episode_title, content)

        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        # 构建Prompt
        system_prompt = """
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

        user_prompt = f"""
播客标题: {episode_title}
内容类型: {content_type}
内容: {content[:2000]}  <!-- 限制输入长度 -->

请提供详细总结（150-300字）。
"""

        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=500
        )

        return response.choices[0].message.content.strip()

    def _rule_based_summary(self, title: str, content: str) -> str:
        """如果没有LLM，使用规则生成基本总结"""
        # 关键词提取
        import re

        # 提取关键句子
        sentences = re.split(r'[.!?]', content)
        important_sentences = [
            s.strip()[:200] for s in sentences
            if any(keyword in s.lower() for keyword in ['key', 'main', 'conclusion', 'important', 'learn', 'feel'])
        ][:3]

        return f"""## 播客总结

**节目**: {title}

{'\n'.join(f"• {s}" for s in important_sentences) if important_sentences else '• ' + content[:150] + '...'}

*（此为快速总结，实际使用时建议绑定OpenAI API）*"""

    async def _get_episode_count(self, subscription_id: int) -> int:
        """获取订阅的单集数量"""
        # 简化实现，实际可缓存
        episodes = await self.repo.get_subscription_episodes(subscription_id, limit=9999)
        return len(episodes)
