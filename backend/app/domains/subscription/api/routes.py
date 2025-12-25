"""Subscription API routes."""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.user.models import User
from app.domains.subscription.services import SubscriptionService
from app.shared.schemas import (
    SubscriptionCreate,
    SubscriptionUpdate,
    SubscriptionResponse,
    PaginatedResponse,
    PaginationParams
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
    results: List[Dict[str, Any]]
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List user's subscriptions."""
    service = SubscriptionService(db, current_user.id)
    return await service.list_subscriptions(
        page=pagination.page,
        size=pagination.size,
        status=status,
        source_type=source_type
    )


@router.post("/", response_model=SubscriptionResponse)
async def create_subscription(
    subscription_data: SubscriptionCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new subscription."""
    service = SubscriptionService(db, current_user.id)
    try:
        return await service.create_subscription(subscription_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/batch", response_model=BatchSubscriptionResponse)
async def create_subscriptions_batch(
    subscriptions_data: List[SubscriptionCreate],
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Batch create subscriptions."""
    service = SubscriptionService(db, current_user.id)
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get subscription by ID."""
    service = SubscriptionService(db, current_user.id)
    result = await service.get_subscription(subscription_id)
    if not result:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return result


@router.put("/{subscription_id}", response_model=SubscriptionResponse)
async def update_subscription(
    subscription_id: int,
    subscription_data: SubscriptionUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Update subscription."""
    service = SubscriptionService(db, current_user.id)
    result = await service.update_subscription(subscription_id, subscription_data)
    if not result:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return result


@router.delete("/{subscription_id}")
async def delete_subscription(
    subscription_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete subscription."""
    service = SubscriptionService(db, current_user.id)
    success = await service.delete_subscription(subscription_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return {"message": "Subscription deleted"}


@router.post("/{subscription_id}/fetch", response_model=FetchResponse)
async def fetch_subscription_items(
    subscription_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Manually trigger subscription fetch (RSS feeds only)."""
    service = SubscriptionService(db, current_user.id)
    try:
        result = await service.fetch_subscription(subscription_id)
        return FetchResponse(**result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch failed: {str(e)}")


@router.post("/fetch-all", response_model=List[FetchResponse])
async def fetch_all_subscriptions(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Fetch all active RSS subscriptions."""
    service = SubscriptionService(db, current_user.id)
    results = await service.fetch_all_subscriptions()
    return [FetchResponse(**r) for r in results]


# Subscription Item endpoints
@router.get("/{subscription_id}/items/", response_model=PaginatedResponse)
async def get_subscription_items(
    subscription_id: int,
    pagination: PaginationParams = Depends(),
    unread_only: bool = Query(False, description="Only show unread items"),
    bookmarked_only: bool = Query(False, description="Only show bookmarked items"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get items from a subscription."""
    service = SubscriptionService(db, current_user.id)
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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all items from all subscriptions."""
    service = SubscriptionService(db, current_user.id)
    return await service.get_all_items(
        page=pagination.page,
        size=pagination.size,
        unread_only=unread_only,
        bookmarked_only=bookmarked_only
    )


@router.post("/items/{item_id}/read")
async def mark_item_as_read(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Mark an item as read."""
    service = SubscriptionService(db, current_user.id)
    result = await service.mark_item_as_read(item_id)
    if not result:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.post("/items/{item_id}/unread")
async def mark_item_as_unread(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Mark an item as unread."""
    service = SubscriptionService(db, current_user.id)
    result = await service.mark_item_as_unread(item_id)
    if not result:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.post("/items/{item_id}/bookmark")
async def toggle_bookmark(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Toggle item bookmark status."""
    service = SubscriptionService(db, current_user.id)
    result = await service.toggle_bookmark(item_id)
    if not result:
        raise HTTPException(status_code=404, detail="Item not found")
    return result


@router.delete("/items/{item_id}")
async def delete_item(
    item_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete an item."""
    service = SubscriptionService(db, current_user.id)
    success = await service.delete_item(item_id)
    if not success:
        raise HTTPException(status_code=404, detail="Item not found")
    return {"message": "Item deleted"}


@router.get("/items/unread-count")
async def get_unread_count(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get total unread items count."""
    service = SubscriptionService(db, current_user.id)
    count = await service.get_unread_count()
    return {"unread_count": count}


# Category endpoints
@router.get("/categories/", response_model=List[CategoryResponse])
async def list_categories(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get all user's categories."""
    service = SubscriptionService(db, current_user.id)
    return await service.list_categories()


@router.post("/categories/", response_model=CategoryResponse)
async def create_category(
    category_data: CategoryCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new category."""
    service = SubscriptionService(db, current_user.id)
    return await service.create_category(
        name=category_data.name,
        description=category_data.description,
        color=category_data.color
    )


@router.put("/categories/{category_id}", response_model=CategoryResponse)
async def update_category(
    category_id: int,
    category_data: CategoryUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Update category."""
    service = SubscriptionService(db, current_user.id)
    update_data = category_data.model_dump(exclude_unset=True)
    result = await service.update_category(category_id, **update_data)
    if not result:
        raise HTTPException(status_code=404, detail="Category not found")
    return result


@router.delete("/categories/{category_id}")
async def delete_category(
    category_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete category."""
    service = SubscriptionService(db, current_user.id)
    success = await service.delete_category(category_id)
    if not success:
        raise HTTPException(status_code=404, detail="Category not found")
    return {"message": "Category deleted"}


@router.post("/{subscription_id}/categories/{category_id}")
async def add_subscription_to_category(
    subscription_id: int,
    category_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Add subscription to category."""
    service = SubscriptionService(db, current_user.id)
    success = await service.add_subscription_to_category(subscription_id, category_id)
    if not success:
        raise HTTPException(status_code=404, detail="Subscription or category not found")
    return {"message": "Subscription added to category"}


@router.delete("/{subscription_id}/categories/{category_id}")
async def remove_subscription_from_category(
    subscription_id: int,
    category_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Remove subscription from category."""
    service = SubscriptionService(db, current_user.id)
    success = await service.remove_subscription_from_category(subscription_id, category_id)
    if not success:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return {"message": "Subscription removed from category"}
