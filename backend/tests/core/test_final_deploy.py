"""Core deployment sanity tests for current podcast architecture."""

from pathlib import Path

from fastapi import APIRouter


def test_service_files_exist() -> None:
    backend_root = Path(__file__).resolve().parents[2]
    files = [
        "app/domains/podcast/models.py",
        "app/domains/podcast/repositories.py",
        "app/domains/podcast/services/__init__.py",
        "app/domains/podcast/api/routes.py",
        "app/domains/ai/llm_privacy.py",
        "app/domains/podcast/integration/security.py",
    ]
    for file in files:
        assert (backend_root / file).exists(), f"Missing required file: {file}"


def test_api_routes_shape() -> None:
    from app.domains.podcast.api.routes import router

    assert isinstance(router, APIRouter)
    assert router.prefix == ""

    paths = [route.path for route in router.routes]
    assert any("/episodes" in path for path in paths)
    assert any("/reports" in path for path in paths)
    assert any("/queue" in path for path in paths)


def test_repository_contract() -> None:
    from app.domains.podcast.repositories import PodcastRepository

    methods = [
        "create_or_update_subscription",
        "create_or_update_episode",
        "update_ai_summary",
        "update_playback_progress",
    ]
    for method in methods:
        assert hasattr(PodcastRepository, method)


def test_specialized_service_contracts() -> None:
    from app.domains.podcast.services.episode_service import PodcastEpisodeService
    from app.domains.podcast.services.playback_service import PodcastPlaybackService
    from app.domains.podcast.services.subscription_service import (
        PodcastSubscriptionService,
    )
    from app.domains.podcast.services.summary_service import PodcastSummaryService

    assert hasattr(PodcastSubscriptionService, "add_subscription")
    assert hasattr(PodcastEpisodeService, "get_episode_with_summary")
    assert hasattr(PodcastPlaybackService, "update_playback_progress")
    assert hasattr(PodcastSummaryService, "regenerate_summary")

