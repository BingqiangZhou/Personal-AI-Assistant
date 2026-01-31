"""
Podcast Summary Service - Manages AI-generated summaries for podcast episodes.

播客总结服务 - 管理播客单集的AI生成总结
"""

import asyncio
import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.redis import PodcastRedis
from app.domains.ai.llm_privacy import ContentSanitizer
from app.domains.podcast.models import PodcastEpisode
from app.domains.podcast.repositories import PodcastRepository


logger = logging.getLogger(__name__)


class PodcastSummaryService:
    """
    Service for managing AI-generated podcast summaries.

    Handles:
    - Generating AI summaries for episodes
    - Retrieving summaries
    - Managing summary generation tasks
    """

    def __init__(self, db: AsyncSession, user_id: int):
        """
        Initialize summary service.

        Args:
            db: Database session
            user_id: Current user ID
        """
        self.db = db
        self.user_id = user_id
        self.repo = PodcastRepository(db)
        self.redis = PodcastRedis()

        # AI text generation service
        from app.domains.ai.services import TextGenerationService
        self.sanitizer = ContentSanitizer(mode=settings.LLM_CONTENT_SANITIZE_MODE)
        self.text_generation = TextGenerationService(db)

    async def generate_summary_for_episode(self, episode_id: int) -> str:
        """
        Generate AI summary for an episode (synchronous).

        Args:
            episode_id: Episode ID

        Returns:
            Generated summary text

        Raises:
            ValueError: If episode not found
        """
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        if episode.ai_summary:
            return episode.ai_summary

        return await self._generate_summary(episode)

    async def regenerate_summary(
        self,
        episode_id: int,
        force: bool = False
    ) -> str:
        """
        Regenerate summary for an episode.

        Args:
            episode_id: Episode ID
            force: Force regeneration even if summary exists

        Returns:
            Generated summary text

        Raises:
            ValueError: If episode not found
        """
        episode = await self.repo.get_episode_by_id(episode_id, self.user_id)
        if not episode:
            raise ValueError("Episode not found")

        if episode.ai_summary and not force:
            return episode.ai_summary

        return await self._generate_summary(episode, version="v2")

    async def get_pending_summaries(self) -> list[dict]:
        """
        Get list of episodes pending summary generation.

        Returns:
            List of episode dicts awaiting summary
        """
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

    async def _generate_summary(
        self,
        episode: PodcastEpisode,
        version: str = "v1"
    ) -> str:
        """
        Core AI summary generation logic.

        Args:
            episode: Podcast episode
            version: Summary version (v1, v2, etc.)

        Returns:
            Generated summary text
        """
        # Check lock to prevent duplicate processing
        lock_key = f"summary:{episode.id}"
        if not await self.redis.acquire_lock(lock_key, expire=300):
            return await self._wait_for_existing_summary(episode, None)

        try:
            # Prepare content and generate summary
            raw_content, content_type, has_transcript = self._prepare_episode_content(episode)
            sanitized_prompt = self._sanitize_content(raw_content, self.sanitizer, content_type)

            # Generate and save summary
            summary = await self._call_llm_for_summary(
                episode_title=episode.title,
                content=sanitized_prompt,
                content_type=content_type
            )

            await self.repo.update_ai_summary(
                episode.id,
                summary,
                version=version,
                transcript_used=has_transcript
            )

            logger.info(f"AI summary completed for episode:{episode.id} ({content_type})")
            return summary

        except Exception as e:
            logger.error(f"Failed to generate AI summary for episode:{episode.id}: {e}")
            await self.repo.mark_summary_failed(episode.id, str(e))
            raise
        finally:
            await self.redis.release_lock(lock_key)

    async def _generate_summary_task(self, episode: PodcastEpisode):
        """
        Background task: Asynchronously generate AI summary.

        Note: This method runs in a separate background task and creates
        its own database session to avoid SQLAlchemy concurrency errors.

        Args:
            episode: Podcast episode object
        """
        from app.core.database import async_session_factory
        from app.domains.ai.llm_privacy import ContentSanitizer

        # Create independent database session
        async with async_session_factory() as session:
            try:
                # Create independent repo and sanitizer instances
                repo = PodcastRepository(session, PodcastRedis())
                sanitizer = ContentSanitizer(mode=settings.LLM_CONTENT_SANITIZE_MODE)

                # Check if summary is needed
                await session.rollback()
                stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode.id)
                result = await session.execute(stmt)
                fresh_episode = result.scalar_one_or_none()

                if not fresh_episode:
                    logger.warning(f"Episode {episode.id} does not exist, skipping summary generation")
                    return

                if fresh_episode.ai_summary:
                    logger.info(f"Episode {episode.id} already has summary, skipping")
                    return

                # Generate summary using independent session
                await self._generate_summary_with_session(
                    fresh_episode, session, repo, sanitizer
                )

            except Exception as e:
                logger.error(f"Async summary failed for episode:{episode.id}: {e}", exc_info=True)
                try:
                    await repo.mark_summary_failed(episode.id, str(e))
                except Exception as db_error:
                    logger.error(f"Failed to mark summary failure for episode:{episode.id}: {db_error}")

    async def _generate_summary_with_session(
        self,
        episode: PodcastEpisode,
        session: AsyncSession,
        repo: PodcastRepository,
        sanitizer: ContentSanitizer
    ) -> str:
        """
        Generate AI summary using specified database session.

        Args:
            episode: Podcast episode object
            session: SQLAlchemy async session
            repo: Podcast repository object
            sanitizer: Content sanitizer

        Returns:
            Generated summary text
        """
        # Check lock to prevent duplicate processing
        lock_key = f"summary:{episode.id}"
        if not await self.redis.acquire_lock(lock_key, expire=300):
            return await self._wait_for_existing_summary(episode, session)

        try:
            # Prepare content and generate summary
            raw_content, content_type, has_transcript = self._prepare_episode_content(episode)
            sanitized_prompt = self._sanitize_content(raw_content, sanitizer, content_type)

            # Generate and save summary
            summary = await self._call_llm_for_summary(
                episode_title=episode.title,
                content=sanitized_prompt,
                content_type=content_type
            )

            await repo.update_ai_summary(
                episode.id,
                summary,
                version="v1",
                transcript_used=has_transcript
            )

            logger.info(f"AI summary completed for episode:{episode.id} ({content_type})")
            return summary

        except Exception as e:
            logger.error(f"Failed to generate AI summary for episode:{episode.id}: {e}")
            await repo.mark_summary_failed(episode.id, str(e))
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
        Call LLM API to generate summary with fallback mechanism.

        Args:
            episode_title: Episode title
            content: Episode content (transcript or description)
            content_type: Content type (transcript/description)

        Returns:
            Generated summary text
        """
        # Delegate to AI domain service
        return await self.text_generation.generate_podcast_summary(
            episode_title=episode_title,
            content=content,
            content_type=content_type,
            max_tokens=500
        )

    def _prepare_episode_content(self, episode: PodcastEpisode) -> tuple[str, str, bool]:
        """
        Prepare episode content for summarization.

        Args:
            episode: Podcast episode

        Returns:
            Tuple of (content, content_type, has_transcript)
        """
        if episode.transcript_content:
            return episode.transcript_content, "transcript", True
        else:
            return episode.description, "description", False

    def _sanitize_content(
        self,
        raw_content: str,
        sanitizer,
        content_type: str
    ) -> str:
        """
        Sanitize content and validate.

        Args:
            raw_content: Raw content
            sanitizer: Content sanitizer
            content_type: Content type identifier

        Returns:
            Sanitized content

        Raises:
            ValueError: If content is too short or fully filtered
        """
        sanitized_prompt = sanitizer.sanitize(
            raw_content, self.user_id, f"podcast_{content_type}"
        )

        if not sanitized_prompt or len(sanitized_prompt.strip()) < 10:
            raise ValueError("Content too short or fully filtered")

        return sanitized_prompt

    async def _wait_for_existing_summary(
        self,
        episode: PodcastEpisode,
        session: Optional[AsyncSession]
    ) -> str:
        """
        Wait for existing summary task to complete.

        Args:
            episode: Podcast episode
            session: Optional database session

        Returns:
            Generated summary text

        Raises:
            ValueError: If wait timeout
        """
        logger.info(f"Summary task already in progress: episode_id={episode.id}")
        current_try = 0

        while current_try < 5:
            await asyncio.sleep(2)

            if session:
                stmt = select(PodcastEpisode).where(PodcastEpisode.id == episode.id)
                result = await session.execute(stmt)
                episode_check = result.scalar_one_or_none()
            else:
                episode_check = await self.repo.get_episode_by_id(episode.id)

            if episode_check and episode_check.ai_summary:
                return episode_check.ai_summary

            current_try += 1

        raise ValueError("Summary generation timeout")
