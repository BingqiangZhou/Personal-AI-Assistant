"""Response assemblers for the subscription API layer.

Converts ORM models / domain objects into API response payloads.
Services return domain objects; these functions handle serialisation.
"""

from __future__ import annotations

from app.shared.schemas import PaginatedResponse, SubscriptionResponse


def assemble_subscription_response(sub, *, item_count: int = 0) -> SubscriptionResponse:
    return SubscriptionResponse(
        id=sub.id,
        title=sub.title,
        description=sub.description,
        source_type=sub.source_type,
        source_url=sub.source_url,
        image_url=sub.image_url,
        config=sub.config,
        status=sub.status,
        last_fetched_at=sub.last_fetched_at,
        latest_item_published_at=sub.latest_item_published_at,
        error_message=sub.error_message,
        fetch_interval=sub.fetch_interval,
        item_count=item_count,
        created_at=sub.created_at,
        updated_at=sub.updated_at,
    )


def assemble_paginated_subscription_response(
    items,
    total: int,
    item_counts: dict,
    page: int,
    size: int,
) -> PaginatedResponse:
    return PaginatedResponse.create(
        items=[
            assemble_subscription_response(sub, item_count=item_counts.get(sub.id, 0))
            for sub in items
        ],
        total=total,
        page=page,
        size=size,
    )


def assemble_item_payload(item) -> dict:
    return {
        "id": item.id,
        "subscription_id": item.subscription_id,
        "external_id": item.external_id,
        "title": item.title,
        "content": item.content,
        "summary": item.summary,
        "author": item.author,
        "source_url": item.source_url,
        "image_url": item.image_url,
        "tags": item.tags,
        "metadata": item.metadata_json,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "read_at": item.read_at.isoformat() if item.read_at else None,
        "bookmarked": item.bookmarked,
        "created_at": item.created_at.isoformat(),
    }


def assemble_category_payload(category, *, include_created_at: bool = True) -> dict:
    payload = {
        "id": category.id,
        "name": category.name,
        "description": category.description,
        "color": category.color,
    }
    if include_created_at:
        payload["created_at"] = category.created_at.isoformat()
    return payload
