"""Podcast architecture end-to-end simulation checks (mocked, no external deps)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
async def test_security_and_service_layers_mocked() -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.domains.ai.llm_privacy import ContentSanitizer
    from app.domains.podcast.integration.security import PodcastSecurityValidator
    from app.domains.podcast.services.search_service import PodcastSearchService

    validator = PodcastSecurityValidator()
    sanitizer = ContentSanitizer("standard")

    malicious = "<!DOCTYPE data [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><data>&xxe;</data>"
    is_valid, _ = validator.validate_rss_xml(malicious)
    assert is_valid is False

    sanitized = sanitizer.sanitize("foo@test.com 13800138000", 1, "test")
    assert "[EMAIL_REDACTED]" in sanitized
    assert "[PHONE_REDACTED]" in sanitized

    with patch("app.domains.podcast.services.search_service.PodcastRepository") as mock_repo_cls:
        repo = AsyncMock()
        episode_one = MagicMock()
        episode_one.id = 1
        episode_one.title = "Episode 1"
        episode_one.description = "Description 1"
        episode_one.subscription = MagicMock(title="Podcast A")

        episode_two = MagicMock()
        episode_two.id = 2
        episode_two.title = "Episode 2"
        episode_two.description = "Description 2"
        episode_two.subscription = MagicMock(title="Podcast B")

        repo.get_liked_episodes.return_value = [episode_one, episode_two]
        mock_repo_cls.return_value = repo

        service = PodcastSearchService(AsyncMock(spec=AsyncSession), user_id=1)
        recommendations = await service.get_recommendations(limit=20)
        assert len(recommendations) == 2


@pytest.mark.asyncio
async def test_routes_aggregator_exports_endpoints() -> None:
    from app.domains.podcast.api.routes import router

    paths = {route.path for route in router.routes}
    assert any("/episodes" in path for path in paths)
    assert any("/reports" in path for path in paths)
    assert any("/queue" in path for path in paths)


@pytest.mark.asyncio
async def test_subscription_service_mocked_add_subscription() -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.domains.podcast.services.subscription_service import PodcastSubscriptionService

    with patch("app.domains.podcast.services.subscription_service.PodcastRepository") as mock_repo_cls, patch(
        "app.domains.podcast.services.subscription_service.SecureRSSParser"
    ) as mock_parser_cls:
        repo = AsyncMock()
        repo.get_user_subscriptions.return_value = []
        sub = MagicMock()
        sub.id = 1
        repo.create_or_update_subscription.return_value = sub
        repo.create_or_update_episodes_batch.return_value = ([], [])
        mock_repo_cls.return_value = repo

        parser = AsyncMock()
        feed = MagicMock()
        feed.title = "Test"
        feed.description = "Desc"
        feed.link = "https://example.com"
        feed.author = "Author"
        feed.language = "en"
        feed.categories = []
        feed.explicit = False
        feed.image_url = None
        feed.podcast_type = "episodic"
        feed.platform = "generic"
        feed.episodes = []
        parser.fetch_and_parse_feed.return_value = (True, feed, None)
        mock_parser_cls.return_value = parser

        service = PodcastSubscriptionService(AsyncMock(spec=AsyncSession), user_id=1)
        subscription, episodes = await service.add_subscription("https://example.com/feed.xml")
        assert subscription.id == 1
        assert episodes == []

