"""Subscription domain models."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, JSON, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from typing import Optional
import enum

from app.core.database import Base


class SubscriptionType(str, enum.Enum):
    """Subscription source types."""
    RSS = "rss"
    API = "api"
    SOCIAL = "social"
    EMAIL = "email"
    WEBSITE = "website"


class SubscriptionStatus(str, enum.Enum):
    """Subscription status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


class UpdateFrequency(str, enum.Enum):
    """Update frequency for scheduled RSS feed refresh."""
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"


class Subscription(Base):
    """Subscription model for managing information sources."""

    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String(50), nullable=False)
    source_url = Column(String(500), nullable=False)
    config = Column(JSON, nullable=True, default={})
    status = Column(String(20), default=SubscriptionStatus.ACTIVE)
    last_fetched_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    fetch_interval = Column(Integer, default=3600)

    update_frequency = Column(
        String(10),
        nullable=False,
        default=UpdateFrequency.HOURLY.value,
        comment="Update frequency type: HOURLY, DAILY, WEEKLY"
    )
    update_time = Column(
        String(5),
        nullable=True,
        comment="Update time in HH:MM format (24-hour)"
    )
    update_day_of_week = Column(
        Integer,
        nullable=True,
        comment="Day of week for WEEKLY frequency (1=Monday, 7=Sunday)"
    )

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="subscriptions")
    items = relationship("SubscriptionItem", back_populates="subscription", cascade="all, delete-orphan")
    categories = relationship(
        "SubscriptionCategory",
        secondary="subscription_category_mappings",
        back_populates="subscriptions"
    )

    __table_args__ = (
        Index('idx_user_status', 'user_id', 'status'),
        Index('idx_source_type', 'source_type'),
    )

    @property
    def computed_next_update_at(self) -> Optional[datetime]:
        """
        Calculate next update time based on frequency.
        Aligns to the start of the next interval unit based on CURRENT time.
        
        Logic:
        - HOURLY: Next top of the hour (XX:00:00)
        - DAILY: Next midnight (00:00:00)
        - WEEKLY: Next Monday midnight (Monday 00:00:00)
        """
        # Current time in UTC
        now = datetime.utcnow()
        
        if self.update_frequency == UpdateFrequency.HOURLY.value:
            # Align to start of current hour, then add 1 hour
            current_hour = now.replace(minute=0, second=0, microsecond=0)
            return current_hour + timedelta(hours=1)
            
        elif self.update_frequency == UpdateFrequency.DAILY.value:
            # Align to start of current day, then add 1 day
            current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return current_day + timedelta(days=1)
            
        elif self.update_frequency == UpdateFrequency.WEEKLY.value:
            # Align to start of current day
            current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
            # Calculate days until next Monday (0)
            days_ahead = 7 - current_day.weekday() # If Mon(0) -> 7 days. If Sun(6) -> 1 day.
            return current_day + timedelta(days=days_ahead)
            
        return None

    def should_update_now(self) -> bool:
        """
        Check if we should update now based on time passed since last fetch.
        Independent of next_update_at (which shows future Schedule).
        """
        if not self.last_fetched_at:
            return True

        # Calculate boundary relative to LAST FETCH
        last = self.last_fetched_at
        boundary_time = None

        if self.update_frequency == UpdateFrequency.HOURLY.value:
            boundary_time = (last + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
            
        elif self.update_frequency == UpdateFrequency.DAILY.value:
            boundary_time = (last + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
            
        elif self.update_frequency == UpdateFrequency.WEEKLY.value:
            days_ahead = 7 - last.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            boundary_time = (last + timedelta(days=days_ahead)).replace(hour=0, minute=0, second=0, microsecond=0)
            
        if boundary_time and datetime.utcnow() >= boundary_time:
            return True
            
        return False


class SubscriptionItem(Base):
    """Individual items from subscriptions."""

    __tablename__ = "subscription_items"

    id = Column(Integer, primary_key=True, index=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=False)
    external_id = Column(String(255), nullable=True)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    source_url = Column(String(500), nullable=True)
    image_url = Column(String(500), nullable=True)
    tags = Column(JSON, nullable=True, default=[])
    metadata_json = Column("metadata", JSON, nullable=True, default={})
    published_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    bookmarked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    subscription = relationship("Subscription", back_populates="items")

    __table_args__ = (
        Index('idx_subscription_external', 'subscription_id', 'external_id'),
        Index('idx_published_at', 'published_at'),
        Index('idx_read_at', 'read_at'),
        Index('idx_bookmarked', 'bookmarked'),
    )


class SubscriptionCategory(Base):
    """Categories for organizing subscriptions."""

    __tablename__ = "subscription_categories"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    color = Column(String(7), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship("User", back_populates="subscription_categories")
    subscriptions = relationship(
        "Subscription",
        secondary="subscription_category_mappings",
        back_populates="categories"
    )


class SubscriptionCategoryMapping(Base):
    """Many-to-many mapping between subscriptions and categories."""

    __tablename__ = "subscription_category_mappings"

    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), primary_key=True)
    category_id = Column(Integer, ForeignKey("subscription_categories.id"), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)
