"""Tests for subscription route response models.

Verifies that every subscription endpoint returns properly-typed
Pydantic response models and uses bilingual error helpers.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# DELETE /{subscription_id}  ->  MessageResponse
# ---------------------------------------------------------------------------


def test_delete_subscription_returns_message_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.delete_subscription.return_value = True

    response = client.delete("/api/v1/subscriptions/1")

    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["message"] == "Subscription deleted"
    mock_subscription_service.delete_subscription.assert_awaited_once_with(1)


def test_delete_subscription_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.delete_subscription.return_value = False

    response = client.delete("/api/v1/subscriptions/999")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# POST /items/{item_id}/read  ->  ItemReadResponse
# ---------------------------------------------------------------------------


def test_mark_item_as_read_returns_item_read_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    now_iso = datetime.now(UTC).isoformat()
    mock_subscription_service.mark_item_as_read.return_value = {
        "id": 5,
        "read_at": now_iso,
    }

    response = client.post("/api/v1/subscriptions/items/5/read")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 5
    assert data["read_at"] == now_iso
    mock_subscription_service.mark_item_as_read.assert_awaited_once_with(5)


def test_mark_item_as_read_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.mark_item_as_read.return_value = None

    response = client.post("/api/v1/subscriptions/items/999/read")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# POST /items/{item_id}/unread  ->  ItemReadResponse
# ---------------------------------------------------------------------------


def test_mark_item_as_unread_returns_item_read_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.mark_item_as_unread.return_value = {
        "id": 5,
        "read_at": None,
    }

    response = client.post("/api/v1/subscriptions/items/5/unread")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 5
    assert data["read_at"] is None
    mock_subscription_service.mark_item_as_unread.assert_awaited_once_with(5)


def test_mark_item_as_unread_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.mark_item_as_unread.return_value = None

    response = client.post("/api/v1/subscriptions/items/999/unread")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# POST /items/{item_id}/bookmark  ->  ItemBookmarkResponse
# ---------------------------------------------------------------------------


def test_toggle_bookmark_returns_item_bookmark_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.toggle_bookmark.return_value = {
        "id": 7,
        "bookmarked": True,
    }

    response = client.post("/api/v1/subscriptions/items/7/bookmark")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == 7
    assert data["bookmarked"] is True
    mock_subscription_service.toggle_bookmark.assert_awaited_once_with(7)


def test_toggle_bookmark_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.toggle_bookmark.return_value = None

    response = client.post("/api/v1/subscriptions/items/999/bookmark")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# DELETE /items/{item_id}  ->  MessageResponse
# ---------------------------------------------------------------------------


def test_delete_item_returns_message_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.delete_item.return_value = True

    response = client.delete("/api/v1/subscriptions/items/3")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Item deleted"
    mock_subscription_service.delete_item.assert_awaited_once_with(3)


def test_delete_item_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.delete_item.return_value = False

    response = client.delete("/api/v1/subscriptions/items/999")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# GET /items/unread-count  ->  UnreadCountResponse
# ---------------------------------------------------------------------------


def test_get_unread_count_returns_unread_count_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.get_unread_count.return_value = 42

    response = client.get("/api/v1/subscriptions/items/unread-count")

    assert response.status_code == 200
    data = response.json()
    assert data["unread_count"] == 42
    mock_subscription_service.get_unread_count.assert_awaited_once()


# ---------------------------------------------------------------------------
# DELETE /categories/{category_id}  ->  MessageResponse
# ---------------------------------------------------------------------------


def test_delete_category_returns_message_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.delete_category.return_value = True

    response = client.delete("/api/v1/subscriptions/categories/2")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Category deleted"
    mock_subscription_service.delete_category.assert_awaited_once_with(2)


def test_delete_category_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.delete_category.return_value = False

    response = client.delete("/api/v1/subscriptions/categories/999")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# POST /{subscription_id}/categories/{category_id}  ->  MessageResponse
# ---------------------------------------------------------------------------


def test_add_subscription_to_category_returns_message_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.add_subscription_to_category.return_value = True

    response = client.post("/api/v1/subscriptions/1/categories/2")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Subscription added to category"
    mock_subscription_service.add_subscription_to_category.assert_awaited_once_with(
        1, 2
    )


def test_add_subscription_to_category_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.add_subscription_to_category.return_value = False

    response = client.post("/api/v1/subscriptions/999/categories/888")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# DELETE /{subscription_id}/categories/{category_id}  ->  MessageResponse
# ---------------------------------------------------------------------------


def test_remove_subscription_from_category_returns_message_response(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.remove_subscription_from_category.return_value = True

    response = client.delete("/api/v1/subscriptions/1/categories/2")

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "Subscription removed from category"
    mock_subscription_service.remove_subscription_from_category.assert_awaited_once_with(
        1, 2
    )


def test_remove_subscription_from_category_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.remove_subscription_from_category.return_value = False

    response = client.delete("/api/v1/subscriptions/999/categories/888")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# POST /  ->  SubscriptionResponse  (bilingual error on duplicate)
# ---------------------------------------------------------------------------


def test_create_subscription_duplicate_returns_bilingual_400(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.create_subscription.side_effect = ValueError(
        "Already subscribed to: Tech News"
    )

    response = client.post(
        "/api/v1/subscriptions/",
        json={
            "title": "Tech News",
            "source_type": "rss",
            "source_url": "https://example.com/feed.xml",
        },
    )

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# GET /{subscription_id}  ->  SubscriptionResponse  (bilingual 404)
# ---------------------------------------------------------------------------


def test_get_subscription_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.get_subscription.return_value = None

    response = client.get("/api/v1/subscriptions/999")

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# PUT /{subscription_id}  ->  SubscriptionResponse  (bilingual 404)
# ---------------------------------------------------------------------------


def test_update_subscription_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.update_subscription.return_value = None

    response = client.put(
        "/api/v1/subscriptions/999",
        json={"title": "Updated"},
    )

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# PUT /categories/{category_id}  ->  CategoryResponse  (bilingual 404)
# ---------------------------------------------------------------------------


def test_update_category_not_found_returns_bilingual_404(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.update_category.return_value = None

    response = client.put(
        "/api/v1/subscriptions/categories/999",
        json={"name": "Updated"},
    )

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail


# ---------------------------------------------------------------------------
# POST /{subscription_id}/fetch  ->  FetchResponse  (bilingual 400)
# ---------------------------------------------------------------------------


def test_fetch_subscription_error_returns_bilingual_400(
    client: TestClient,
    mock_subscription_service: AsyncMock,
):
    mock_subscription_service.fetch_subscription.side_effect = ValueError(
        "Subscription not found"
    )

    response = client.post("/api/v1/subscriptions/999/fetch")

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "message_en" in detail
    assert "message_zh" in detail
