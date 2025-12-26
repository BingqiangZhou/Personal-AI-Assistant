"""Subscription domain models."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, JSON, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta, timezone
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

    def _parse_update_time(self) -> tuple[int, int]:
        """Parse update_time string (HH:MM) to integers."""
        if not self.update_time:
            return 0, 0
        try:
            parts = self.update_time.split(':')
            if len(parts) == 2:
                return int(parts[0]), int(parts[1])
        except (ValueError, AttributeError):
            pass
        return 0, 0

    def _get_next_scheduled_time(self, base_time: datetime) -> datetime:
        """Calculate the next scheduled time after base_time."""
        hour, minute = self._parse_update_time()
        
        if self.update_frequency == UpdateFrequency.HOURLY.value:
            # Next top of the hour after base_time
            return (base_time + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
            
        elif self.update_frequency == UpdateFrequency.DAILY.value:
            # Scheduled time today
            scheduled = base_time.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if scheduled <= base_time:
                # If already passed today, next one is tomorrow
                scheduled += timedelta(days=1)
            return scheduled
            
        elif self.update_frequency == UpdateFrequency.WEEKLY.value:
            # Default to Monday (0) if not set. DB stores 1-7 (Mon-Sun)
            target_weekday = (self.update_day_of_week - 1) if self.update_day_of_week else 0
            # Scheduled time today
            scheduled = base_time.replace(hour=hour, minute=minute, second=0, microsecond=0)
            
            # Find days until target weekday
            days_ahead = target_weekday - base_time.weekday()
            if days_ahead < 0 or (days_ahead == 0 and scheduled <= base_time):
                days_ahead += 7
                
            return scheduled + timedelta(days=days_ahead)
            
        return base_time + timedelta(hours=1) # Fallback

    @property
    def computed_next_update_at(self) -> Optional[datetime]:
        """
        Calculate next update time based on frequency and user settings.
        Aligns to the next scheduled interval based on CURRENT time.
        """
        return self._get_next_scheduled_time(datetime.now(timezone.utc))

    def should_update_now(self) -> bool:
        """
        Check if we should update now based on time passed since last fetch.
        """
        if not self.last_fetched_at:
            return True

        # Calculate the Earliest next scheduled time AFTER the last fetch
        next_possible = self._get_next_scheduled_time(self.last_fetched_at)
        
        # If the scheduled time has arrived or passed, we should update
        return datetime.utcnow() >= next_possible


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
