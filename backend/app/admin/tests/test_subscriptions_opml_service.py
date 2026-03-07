from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.admin.services.subscriptions_opml_service import AdminSubscriptionsOpmlService
from app.shared.schemas import SubscriptionCreate


class _FakeTaskOrchestrationService:
    def __init__(self, db):
        self.db = db
        self.calls = []

    def enqueue_opml_subscription_episodes(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(id="task-123")


@pytest.mark.asyncio
async def test_import_opml_queues_episode_processing_via_orchestration_service():
    db = AsyncMock()
    global_existing_result = Mock()
    global_existing_result.scalar_one_or_none.return_value = None
    db.execute.return_value = global_existing_result

    user = SimpleNamespace(id=42, username="admin")
    request = Mock()
    subscription = SimpleNamespace(id=99)

    fake_task_service = _FakeTaskOrchestrationService(db)
    service = AdminSubscriptionsOpmlService(
        db,
        task_orchestration_service_factory=lambda session: fake_task_service,
    )
    service._parse_opml = AsyncMock(
        return_value=[
            SubscriptionCreate(
                source_url="https://example.com/feed.xml",
                title="Sample Podcast",
                source_type="podcast-rss",
                description="",
                image_url=None,
            )
        ]
    )

    podcast_service = Mock()
    podcast_service.repo = Mock()
    podcast_service.repo.get_subscription_by_url = AsyncMock(return_value=None)
    podcast_service.repo.create_or_update_subscription = AsyncMock(
        return_value=subscription
    )

    with patch(
        "app.admin.services.subscriptions_opml_service.PodcastSubscriptionService",
        return_value=podcast_service,
    ), patch(
        "app.admin.services.subscriptions_opml_service.log_admin_action",
        new=AsyncMock(),
    ):
        payload, status_code = await service.import_subscriptions_opml(
            request=request,
            user=user,
            opml_content="<opml></opml>",
        )

    assert status_code == 200
    assert payload["results"]["queued_episode_tasks"] == 1
    assert payload["details"][0]["background_task_id"] == "task-123"
    assert fake_task_service.calls == [
        {
            "subscription_id": 99,
            "user_id": 42,
            "source_url": "https://example.com/feed.xml",
        }
    ]