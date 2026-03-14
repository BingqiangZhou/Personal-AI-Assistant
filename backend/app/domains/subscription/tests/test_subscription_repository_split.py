from unittest.mock import AsyncMock

import pytest

from app.domains.subscription.repositories import SubscriptionRepository


def test_subscription_repository_exposes_split_methods():
    repo = SubscriptionRepository(AsyncMock())

    assert callable(repo.get_user_subscriptions)
    assert callable(repo.create_subscription)
    assert callable(repo.get_subscription_items)
    assert callable(repo.update_fetch_status)


@pytest.mark.asyncio
async def test_subscription_repository_unread_count_uses_common_helper(monkeypatch):
    repo = SubscriptionRepository(AsyncMock())
    unread_count = AsyncMock(return_value=4)
    monkeypatch.setattr(repo.db, "scalar", unread_count)

    result = await repo.get_unread_count(7)

    assert result == 4
    unread_count.assert_awaited_once()
