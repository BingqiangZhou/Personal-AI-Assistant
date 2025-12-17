"""Subscription domain models."""

from sqlalchemy import (
    Column, Integer, String, Text, DateTime,
    ForeignKey, Boolean, JSON, Index
)
from sqlalchemy.orm import relationship
from datetime import datetime
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
    fetch_interval = Column(Integer, default=3600)  # seconds
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="subscriptions")
    items = relationship("SubscriptionItem", back_populates="subscription", cascade="all, delete-orphan")

    # Indexes
    __table_args__ = (
        Index('idx_user_status', 'user_id', 'status'),
        Index('idx_source_type', 'source_type'),
    )


class SubscriptionItem(Base):
    """Individual items from subscriptions."""

    __tablename__ = "subscription_items"

    id = Column(Integer, primary_key=True, index=True)
    subscription_id = Column(Integer, ForeignKey("subscriptions.id"), nullable=False)
    external_id = Column(String(255), nullable=True)  # ID from source
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)
    author = Column(String(255), nullable=True)
    source_url = Column(String(500), nullable=True)
    image_url = Column(String(500), nullable=True)
    tags = Column(JSON, nullable=True, default=[])
    metadata_json = Column("metadata", JSON, nullable=True, default={})  # Avoid reserved name
    published_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)
    bookmarked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    subscription = relationship("Subscription", back_populates="items")

    # Indexes
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
    color = Column(String(7), nullable=True)  # Hex color code
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
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