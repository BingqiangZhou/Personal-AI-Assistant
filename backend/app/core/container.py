"""
Dependency Injection Container for the application.

This module provides a centralized dependency injection container using the
dependency-injector library. It manages the lifecycle and dependencies of
all application services.

依赖注入容器 - 使用 dependency-injector 库管理应用程序服务
"""

from dependency_injector import containers, providers
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session_factory
from app.core.redis import PodcastRedis
from app.domains.ai.llm_privacy import ContentSanitizer

# AI domain
from app.domains.ai.services import TextGenerationService
from app.domains.podcast.podcast_service_facade import PodcastService

# Podcast domain
from app.domains.podcast.repositories import PodcastRepository
from app.domains.podcast.services import (
    PodcastEpisodeService,
    PodcastPlaybackService,
    PodcastSearchService,
    PodcastSubscriptionService,
    PodcastSummaryService,
)

# Subscription domain
from app.domains.subscription.repositories import SubscriptionRepository
from app.domains.user.repositories import UserRepository
from app.domains.user.services.auth_service import AuthenticationService


class ApplicationContainer(containers.DeclarativeContainer):
    """
    Main application dependency injection container.

    Provides:
    - Database session factory
    - Repository instances
    - Service instances with proper dependencies injected
    """

    # Configuration
    config = providers.Configuration()

    # Database
    database = providers.Singleton(async_session_factory)

    # Redis
    redis = providers.Factory(PodcastRedis)

    # Core components
    content_sanitizer = providers.Factory(
        ContentSanitizer,
        mode=settings.LLM_CONTENT_SANITIZE_MODE
    )

    # === Repositories ===
    user_repository = providers.Factory(
        UserRepository,
        db=database
    )

    subscription_repository = providers.Factory(
        SubscriptionRepository,
        db=database
    )

    podcast_repository = providers.Factory(
        PodcastRepository,
        db=database,
        redis=redis
    )

    # === AI Services ===
    text_generation_service = providers.Factory(
        TextGenerationService,
        db=database
    )

    # === User Domain Services ===
    authentication_service = providers.Factory(
        AuthenticationService,
        db=database
    )

    # === Podcast Domain Services ===
    # Podcast services are created via factory functions below (lines 169+)
    # because they require user_id at runtime


# Global container instance
container = ApplicationContainer()


def get_container() -> ApplicationContainer:
    """
    Get the global application container.

    Returns:
        ApplicationContainer instance
    """
    return container


def get_podcast_service(db: AsyncSession, user_id: int) -> PodcastService:
    """
    Factory function to get a PodcastService instance.

    This is a convenience function that can be used with FastAPI's Depends.

    Args:
        db: Database session
        user_id: Current user ID

    Returns:
        PodcastService instance
    """
    return PodcastService(db, user_id)


def get_podcast_subscription_service(db: AsyncSession, user_id: int) -> PodcastSubscriptionService:
    """
    Factory function to get a PodcastSubscriptionService instance.

    Args:
        db: Database session
        user_id: Current user ID

    Returns:
        PodcastSubscriptionService instance
    """
    return PodcastSubscriptionService(db, user_id)


def get_podcast_episode_service(db: AsyncSession, user_id: int) -> PodcastEpisodeService:
    """
    Factory function to get a PodcastEpisodeService instance.

    Args:
        db: Database session
        user_id: Current user ID

    Returns:
        PodcastEpisodeService instance
    """
    return PodcastEpisodeService(db, user_id)


def get_podcast_playback_service(db: AsyncSession, user_id: int) -> PodcastPlaybackService:
    """
    Factory function to get a PodcastPlaybackService instance.

    Args:
        db: Database session
        user_id: Current user ID

    Returns:
        PodcastPlaybackService instance
    """
    return PodcastPlaybackService(db, user_id)


def get_podcast_summary_service(db: AsyncSession, user_id: int) -> PodcastSummaryService:
    """
    Factory function to get a PodcastSummaryService instance.

    Args:
        db: Database session
        user_id: Current user ID

    Returns:
        PodcastSummaryService instance
    """
    return PodcastSummaryService(db, user_id)


def get_podcast_search_service(db: AsyncSession, user_id: int) -> PodcastSearchService:
    """
    Factory function to get a PodcastSearchService instance.

    Args:
        db: Database session
        user_id: Current user ID

    Returns:
        PodcastSearchService instance
    """
    return PodcastSearchService(db, user_id)
