"""Subscription API routes."""

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.domains.subscription.api.dependencies import get_subscription_service
from app.domains.subscription.api.routes_podcasts import router as podcast_router
from app.domains.subscription.services import SubscriptionService
from app.shared.schemas import (
    PaginatedResponse,
    PaginationParams,
    SubscriptionCreate,
    SubscriptionResponse,
    SubscriptionUpdate,
)


router = APIRouter()


# Additional request/response models
class CategoryCreate(BaseModel):
    """Request model for creating a category."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


class CategoryResponse(BaseModel):
    """Response model for category."""
    id: int
    name: str
    description: Optional[str]
    color: Optional[str]
    created_at: str


class CategoryUpdate(BaseModel):
    """Request model for updating a category."""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = None
    color: Optional[str] = Field(None, pattern=r"^#[0-9A-Fa-f]{6}$")


class FetchResponse(BaseModel):
    """Response model for fetch operation."""
    subscription_id: int
    status: str
    new_items: Optional[int] = None
    updated_items: Optional[int] = None
    total_items: Optional[int] = None
    error: Optional[str] = None


class BatchSubscriptionResponse(BaseModel):
    """Response model for batch subscription creation."""
    results: list[dict[str, Any]]
    total_requested: int
    success_count: int
    skipped_count: int
    error_count: int


# Subscription endpoints
@router.get("/", response_model=PaginatedResponse)
async def list_subscriptions(
    pagination: PaginationParams = Depends(),
    status: Optional[str] = Query(None, description="Filter by status"),
    source_type: Optional[str] = Query(None, description="Filter by source type"),
    service: SubscriptionService = Depends(get_subscription_service)
):
    """List user's subscriptions."""
    return await service.list_subscriptions(
        page=pagination.page,
        size=pagination.size,
        status=status,
        source_type=source_type
    )


@router.post("/", response_model=SubscriptionResponse)
async def create_subscription(
    subscription_data: SubscriptionCreate,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Create a new subscription.

    If duplicate URL or title is found, returns the existing subscription with a message.
    """

    # Check for duplicate before creation


    # Duplicate detection is now handled at service layer with many-to-many support
    # No duplicate found - create subscription
    try:
        return await service.create_subscription(subscription_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/batch", response_model=BatchSubscriptionResponse)
async def create_subscriptions_batch(
    subscriptions_data: list[SubscriptionCreate],
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Batch create subscriptions."""
    results = await service.create_subscriptions_batch(subscriptions_data)
    
    success_count = sum(1 for r in results if r["status"] == "success")
    skipped_count = sum(1 for r in results if r["status"] == "skipped")
    error_count = sum(1 for r in results if r["status"] == "error")
    
    return BatchSubscriptionResponse(
        results=results,
        total_requested=len(subscriptions_data),
        success_count=success_count,
        skipped_count=skipped_count,
        error_count=error_count
    )


@router.get("/{subscription_id}", response_model=SubscriptionResponse)
async def get_subscription(
    subscription_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Get subscription by ID."""
    result = await service.get_subscription(subscription_id)
    if not result:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return result


@router.put("/{subscription_id}", response_model=SubscriptionResponse)
async def update_subscription(
    subscription_id: int,
    subscription_data: SubscriptionUpdate,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Update subscription."""
    result = await service.update_subscription(subscription_id, subscription_data)
    if not result:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return result


@router.delete("/{subscription_id}")
async def delete_subscription(
    subscription_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Delete subscription."""
    success = await service.delete_subscription(subscription_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return {"message": "Subscription deleted"}


@router.post("/{subscription_id}/fetch", response_model=FetchResponse)
async def fetch_subscription_items(
    subscription_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Manually trigger subscription fetch (RSS feeds only)."""
    try:
        result = await service.fetch_subscription(subscription_id)
        return FetchResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch failed: {str(e)}")


@router.post("/fetch-all", response_model=list[FetchResponse])
async def fetch_all_subscriptions(
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Fetch all active RSS subscriptions."""
    results = await service.fetch_all_subscriptions()
    return [FetchResponse(**r) for r in results]


# Subscription Item endpoints
@router.get("/{subscription_id}/items/", response_model=PaginatedResponse)
async def get_subscription_items(
    subscription_id: int,
    pagination: PaginationParams = Depends(),
    unread_only: bool = Query(False, description="Only show unread items"),
    bookmarked_only: bool = Query(False, description="Only show bookmarked items"),
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Get items from a subscription."""
    return await service.get_subscription_items(
        subscription_id,
        page=pagination.page,
        size=pagination.size,
        unread_only=unread_only,
        bookmarked_only=bookmarked_only
    )


@router.get("/items/all/", response_model=PaginatedResponse)
async def get_all_items(
    pagination: PaginationParams = Depends(),
    unread_only: bool = Query(False, description="Only show unread items"),
    bookmarked_only: bool = Query(False, description="Only show bookmarked items"),
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Get all items from all subscriptions."""
    return await service.get_all_items(
        page=pagination.page,
        size=pagination.size,
        unread_only=unread_only,
        bookmarked_only=bookmarked_only
    )


@router.post("/items/{item_id}/read")
async def mark_item_as_read(
    item_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Mark an item as read."""
    result = await service.mark_item_as_read(item_id)
    if not result:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.post("/items/{item_id}/unread")
async def mark_item_as_unread(
    item_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Mark an item as unread."""
    result = await service.mark_item_as_unread(item_id)
    if not result:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.post("/items/{item_id}/bookmark")
async def toggle_bookmark(
    item_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Toggle item bookmark status."""
    result = await service.toggle_bookmark(item_id)
    if not result:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.delete("/items/{item_id}")
async def delete_item(
    item_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Delete an item."""
    success = await service.delete_item(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted"}


@router.get("/items/unread-count")
async def get_unread_count(
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Get total unread items count."""
    count = await service.get_unread_count()
    return {"unread_count": count}


# Category endpoints
@router.get("/categories/", response_model=list[CategoryResponse])
async def list_categories(
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Get all user's categories."""
    return await service.list_categories()


@router.post("/categories/", response_model=CategoryResponse)
async def create_category(
    category_data: CategoryCreate,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Create a new category."""
    return await service.create_category(
        name=category_data.name,
        description=category_data.description,
        color=category_data.color
    )


@router.put("/categories/{category_id}", response_model=CategoryResponse)
async def update_category(
    category_id: int,
    category_data: CategoryUpdate,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Update category."""
    update_data = category_data.model_dump(exclude_unset=True)
    result = await service.update_category(category_id, **update_data)
    if not result:
        raise HTTPException(status_code=404, detail="Category not found")
    return result


@router.delete("/categories/{category_id}")
async def delete_category(
    category_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Delete category."""
    success = await service.delete_category(category_id)
    if not success:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted"}


@router.post("/{subscription_id}/categories/{category_id}")
async def add_subscription_to_category(
    subscription_id: int,
    category_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Add subscription to category."""
    success = await service.add_subscription_to_category(subscription_id, category_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription or category not found")
    return {"message": "Subscription added to category"}


@router.delete("/{subscription_id}/categories/{category_id}")
async def remove_subscription_from_category(
    subscription_id: int,
    category_id: int,
    service: SubscriptionService = Depends(get_subscription_service)
):
    """Remove subscription from category."""
    success = await service.remove_subscription_from_category(subscription_id, category_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return {"message": "Subscription removed from category"}


router.include_router(podcast_router)
