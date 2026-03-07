from unittest.mock import AsyncMock

import pytest

from app.domains.subscription.services import SubscriptionService


@pytest.mark.asyncio
async def test_subscription_service_delegates_query_calls():
    service = SubscriptionService(AsyncMock(), user_id=11)
    expected = object()
    service.query_service.get_subscription = AsyncMock(return_value=expected)

    result = await service.get_subscription(5)

    assert result is expected
    service.query_service.get_subscription.assert_awaited_once_with(5)


@pytest.mark.asyncio
async def test_subscription_service_delegates_fetch_calls():
    service = SubscriptionService(AsyncMock(), user_id=11)
    expected = {"status": "success"}
    service.fetch_service.fetch_all_subscriptions = AsyncMock(return_value=expected)

    result = await service.fetch_all_subscriptions()

    assert result is expected
    service.fetch_service.fetch_all_subscriptions.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_subscription_service_delegates_category_calls():
    service = SubscriptionService(AsyncMock(), user_id=11)
    expected = {"id": 1, "name": "Tech"}
    service.category_service.create_category = AsyncMock(return_value=expected)

    result = await service.create_category("Tech", "desc", "#ffffff")

    assert result is expected
    service.category_service.create_category.assert_awaited_once_with(
        "Tech",
        "desc",
        "#ffffff",
    )