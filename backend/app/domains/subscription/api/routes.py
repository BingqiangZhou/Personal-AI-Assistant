"""Subscription API routes."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db_session
from app.core.dependencies import get_current_active_user
from app.domains.user.models import User
from app.shared.schemas import (
    SubscriptionCreate,
    SubscriptionUpdate,
    SubscriptionResponse,
    PaginatedResponse,
    PaginationParams
)

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def list_subscriptions(
    pagination: PaginationParams = Depends(),
    status: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """List user's subscriptions."""
    # TODO: Implement subscription listing
    pass


@router.post("/", response_model=SubscriptionResponse)
async def create_subscription(
    subscription_data: SubscriptionCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Create a new subscription."""
    # TODO: Implement subscription creation
    pass


@router.get("/{subscription_id}", response_model=SubscriptionResponse)
async def get_subscription(
    subscription_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Get subscription by ID."""
    # TODO: Implement subscription retrieval
    pass


@router.put("/{subscription_id}", response_model=SubscriptionResponse)
async def update_subscription(
    subscription_id: int,
    subscription_data: SubscriptionUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Update subscription."""
    # TODO: Implement subscription update
    pass


@router.delete("/{subscription_id}")
async def delete_subscription(
    subscription_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Delete subscription."""
    # TODO: Implement subscription deletion
    pass


@router.post("/{subscription_id}/fetch")
async def fetch_subscription_items(
    subscription_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db_session)
):
    """Manually trigger subscription fetch."""
    # TODO: Implement manual fetch
    pass