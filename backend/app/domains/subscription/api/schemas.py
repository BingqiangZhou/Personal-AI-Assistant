"""Subscription API request/response schemas."""

from typing import Any

from pydantic import BaseModel, Field


class CategoryCreate(BaseModel):
    """Request model for creating a category."""

    name: str = Field(..., min_length=1, max_length=100)
    description: str | None = None
    color: str | None = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


class CategoryResponse(BaseModel):
    """Response model for category."""

    id: int
    name: str
    description: str | None
    color: str | None
    created_at: str


class CategoryUpdate(BaseModel):
    """Request model for updating a category."""

    name: str | None = Field(None, min_length=1, max_length=100)
    description: str | None = None
    color: str | None = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


class FetchResponse(BaseModel):
    """Response model for fetch operation."""

    subscription_id: int
    status: str
    new_items: int | None = None
    updated_items: int | None = None
    total_items: int | None = None
    error: str | None = None


class BatchSubscriptionResponse(BaseModel):
    """Response model for batch subscription creation."""

    results: list[dict[str, Any]]
    total_requested: int
    success_count: int
    skipped_count: int
    error_count: int


class MessageResponse(BaseModel):
    """Generic message response for delete/association endpoints."""

    message: str


class ItemReadResponse(BaseModel):
    """Response model for mark-as-read / mark-as-unread."""

    id: int
    read_at: str | None = None


class ItemBookmarkResponse(BaseModel):
    """Response model for bookmark toggle."""

    id: int
    bookmarked: bool


class UnreadCountResponse(BaseModel):
    """Response model for unread count."""

    unread_count: int


class SubscriptionItemResponse(BaseModel):
    """Response model for a single subscription item."""

    id: int
    subscription_id: int
    external_id: str | None = None
    title: str
    content: str | None = None
    summary: str | None = None
    author: str | None = None
    source_url: str | None = None
    image_url: str | None = None
    tags: list[str] | None = None
    metadata: dict[str, Any] | None = None
    published_at: str | None = None
    read_at: str | None = None
    bookmarked: bool = False
    created_at: str
