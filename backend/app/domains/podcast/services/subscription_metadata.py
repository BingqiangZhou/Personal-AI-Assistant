"""Shared helpers for subscription metadata normalization."""

from __future__ import annotations

from typing import Any

from app.domains.subscription.models import Subscription


def normalize_categories(raw_categories: list[Any]) -> list[dict[str, str]]:
    """Normalize categories to stable dict payloads."""
    categories: list[dict[str, str]] = []
    for category in raw_categories:
        if isinstance(category, str):
            categories.append({"name": category})
        elif isinstance(category, dict):
            name = category.get("name")
            categories.append({"name": str(name) if name is not None else ""})
        else:
            categories.append({"name": str(category)})
    return categories


def extract_subscription_metadata(
    subscription: Subscription, *, normalize_category_items: bool = True
) -> dict[str, Any]:
    """Extract normalized metadata fields with image URL fallback."""
    config = subscription.config or {}
    image_url = config.get("image_url") or subscription.image_url
    raw_categories = config.get("categories") or []
    categories = (
        normalize_categories(raw_categories)
        if normalize_category_items
        else raw_categories
    )

    return {
        "image_url": image_url,
        "author": config.get("author"),
        "platform": config.get("platform"),
        "categories": categories,
        "podcast_type": config.get("podcast_type"),
        "language": config.get("language"),
        "explicit": config.get("explicit", False),
        "link": config.get("link"),
        "total_episodes_from_config": config.get("total_episodes"),
    }
