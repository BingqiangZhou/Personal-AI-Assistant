"""Podcast data models - core podcast domain.

Contains podcast-specific models: episodes, playback state, and queue.
Subscription models merged from subscription domain.
Media and content models have been split into their own domains
but are re-exported here for backward compatibility.
"""

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


# ---------------------------------------------------------------------------
# Podcast-domain models (live here permanently)
# ---------------------------------------------------------------------------


class PodcastEpisode(Base):
    """Podcast episode data model.

    Design notes:
    - Uses foreign key to Subscription rather than inheritance
    - Reuses some SubscriptionItem fields but independently manages
      podcast-specific audio/summary fields
    - Maintains compatibility with existing schemas while avoiding
      complex SQLAlchemy inheritance configuration
    """

    __tablename__ = "podcast_episodes"

    id = Column(Integer, primary_key=True)
    subscription_id = Column(
        Integer, ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False
    )

    # Podcast basic information
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=False)

    # Audio information
    audio_url = Column(String(500), nullable=False)
    audio_duration = Column(Integer)  # seconds
    audio_file_size = Column(Integer)  # bytes

    # Transcript
    transcript_url = Column(String(500))

    # AI summary
    ai_summary = Column(Text)
    summary_version = Column(String(50))  # Track summary version
    ai_confidence_score = Column(Float)  # AI summary quality score

    # Episode image
    image_url = Column(String(500))  # Episode cover image URL

    # Episode detail page link
    item_link = Column(
        String(500),
        unique=True,
        nullable=False,
    )  # <item><link> tag content, links to episode detail page

    # Playback statistics (global)
    play_count = Column(Integer, default=0)
    last_played_at = Column(DateTime(timezone=True))

    # Episode information
    season = Column(Integer)
    episode_number = Column(Integer)
    explicit = Column(Boolean, default=False)

    # Status and metadata
    status = Column(
        String(50),
        default="pending_summary",
    )  # pending, summarized, failed
    metadata_json = Column(
        "metadata",
        JSON,
        nullable=True,
        default=dict,
    )  # Renamed to avoid SQLAlchemy reserved attribute
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    subscription = relationship("Subscription", back_populates="podcast_episodes")
    playback_states = relationship(
        "PodcastPlaybackState",
        back_populates="episode",
        cascade="all, delete",
    )
    queue_items = relationship(
        "PodcastQueueItem",
        back_populates="episode",
        cascade="all, delete",
    )
    daily_report_items = relationship(
        "PodcastDailyReportItem",
        back_populates="episode",
        cascade="all, delete",
    )
    transcript = relationship(
        "PodcastEpisodeTranscript",
        back_populates="episode",
        uselist=False,
        cascade="all, delete",
    )

    # Indexes
    __table_args__ = (
        Index("idx_podcast_subscription", "subscription_id"),
        Index("idx_podcast_status", "status"),
        Index("idx_podcast_published", "published_at"),
        Index(
            "idx_podcast_episodes_status_published_id", "status", "published_at", "id"
        ),
        Index("idx_podcast_episode_image", "image_url"),
        Index("idx_podcast_episodes_item_link", "item_link", unique=True),
    )

    def __repr__(self):
        return f"<PodcastEpisode(id={self.id}, title='{self.title[:30]}...', status='{self.status}')>"


class PodcastPlaybackState(Base):
    """User playback state - tracks each user's podcast playback progress."""

    __tablename__ = "podcast_playback_states"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    episode_id = Column(
        Integer,
        ForeignKey("podcast_episodes.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Playback state
    current_position = Column(Integer, default=0)  # Current playback position (seconds)
    is_playing = Column(Boolean, default=False)
    playback_rate = Column(Float, default=1.0, nullable=False)  # Playback speed
    last_updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Statistics
    play_count = Column(Integer, default=0)

    # Relationships
    episode = relationship("PodcastEpisode", back_populates="playback_states")
    # Note: User model not imported; accessed via repositories only

    __table_args__ = (
        CheckConstraint(
            "playback_rate >= 0.5 AND playback_rate <= 3.0",
            name="ck_podcast_playback_states_playback_rate_range",
        ),
        # Ensure each user-episode combination is unique
        Index("idx_user_episode_unique", "user_id", "episode_id", unique=True),
    )

    def __repr__(self):
        return f"<PlaybackState(user={self.user_id}, ep={self.episode_id}, pos={self.current_position}s)>"


class PodcastQueue(Base):
    """Per-user persistent podcast playback queue."""

    __tablename__ = "podcast_queues"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    current_episode_id = Column(
        Integer,
        ForeignKey("podcast_episodes.id", ondelete="SET NULL"),
        nullable=True,
    )
    revision = Column(Integer, default=0, nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    items = relationship(
        "PodcastQueueItem",
        back_populates="queue",
        cascade="all, delete-orphan",
        order_by="PodcastQueueItem.position",
    )
    current_episode = relationship(
        "PodcastEpisode",
        foreign_keys=[current_episode_id],
        lazy="joined",
    )

    __table_args__ = (Index("idx_podcast_queue_user", "user_id"),)

    def __repr__(self):
        return f"<PodcastQueue(user={self.user_id}, current={self.current_episode_id}, revision={self.revision})>"


class PodcastQueueItem(Base):
    """Item in a user's podcast queue."""

    __tablename__ = "podcast_queue_items"

    id = Column(Integer, primary_key=True)
    queue_id = Column(
        Integer,
        ForeignKey("podcast_queues.id", ondelete="CASCADE"),
        nullable=False,
    )
    episode_id = Column(
        Integer,
        ForeignKey("podcast_episodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    position = Column(Integer, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    queue = relationship("PodcastQueue", back_populates="items")
    episode = relationship("PodcastEpisode", back_populates="queue_items")

    __table_args__ = (
        UniqueConstraint(
            "queue_id",
            "episode_id",
            name="uq_podcast_queue_item_episode",
        ),
        UniqueConstraint("queue_id", "position", name="uq_podcast_queue_item_position"),
        Index("idx_podcast_queue_items_queue_position", "queue_id", "position"),
    )

    def __repr__(self):
        return f"<PodcastQueueItem(queue={self.queue_id}, episode={self.episode_id}, position={self.position})>"



# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def is_podcast_subscription(subscription) -> bool:
    """Check whether a Subscription is a podcast type."""
    return subscription.source_type == "podcast-rss"


# ---------------------------------------------------------------------------
# Subscription domain models (merged from domains/subscription)
# ---------------------------------------------------------------------------


class SubscriptionType(StrEnum):
    """Subscription source types."""

    RSS = "rss"
    API = "api"
    SOCIAL = "social"
    EMAIL = "email"
    WEBSITE = "website"


class SubscriptionStatus(StrEnum):
    """Subscription status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"


class UpdateFrequency(StrEnum):
    """Update frequency for scheduled RSS feed refresh."""

    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"


class Subscription(Base):
    """Subscription model for managing information sources.

    Represents a subscription source (e.g., RSS feed) that can be
    subscribed to by multiple users via the UserSubscription mapping table.
    """

    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_type = Column(String(50), nullable=False)
    source_url = Column(String(500), nullable=False)
    image_url = Column(String(500), nullable=True)
    config = Column(JSON, nullable=True, default=dict)
    status = Column(String(20), default=SubscriptionStatus.ACTIVE)
    last_fetched_at = Column(DateTime(timezone=True), nullable=True)
    latest_item_published_at = Column(
        DateTime(timezone=True),
        nullable=True,
        comment="Published timestamp of the latest item from this feed",
    )
    error_message = Column(Text, nullable=True)
    fetch_interval = Column(Integer, default=3600)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    user_subscriptions = relationship(
        "UserSubscription", back_populates="subscription", cascade="all, delete-orphan"
    )
    podcast_episodes = relationship(
        "PodcastEpisode",
        back_populates="subscription",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("source_url", "source_type", name="uq_subscriptions_source"),
        Index("idx_source_type", "source_type"),
        Index("idx_source_url", "source_url"),
    )


class UserSubscription(Base):
    """Many-to-many mapping between users and subscriptions.

    Allows multiple users to subscribe to the same subscription source
    while maintaining user-specific settings like update frequency
    and archive status.
    """

    __tablename__ = "user_subscriptions"

    id = Column(Integer, primary_key=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    subscription_id = Column(
        Integer, ForeignKey("subscriptions.id", ondelete="CASCADE"), nullable=False
    )

    # User-specific settings
    update_frequency = Column(
        String(10),
        nullable=True,
        default=UpdateFrequency.HOURLY.value,
        comment="Update frequency type: HOURLY, DAILY, WEEKLY",
    )
    update_time = Column(
        String(5),
        nullable=True,
        comment="Update time in HH:MM format (24-hour)",
    )
    update_day_of_week = Column(
        Integer,
        nullable=True,
        comment="Day of week for WEEKLY frequency (1=Monday, 7=Sunday)",
    )

    # User-specific state
    is_archived = Column(
        Boolean, default=False, comment="User has archived this subscription"
    )
    playback_rate_preference = Column(
        Float,
        nullable=True,
        comment="Subscription-level playback speed preference",
    )

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    subscription = relationship("Subscription", back_populates="user_subscriptions")

    __table_args__ = (
        CheckConstraint(
            "playback_rate_preference IS NULL OR "
            "(playback_rate_preference >= 0.5 AND playback_rate_preference <= 3.0)",
            name="ck_user_subscriptions_playback_rate_preference_range",
        ),
        Index("idx_user_subscription", "user_id", "subscription_id", unique=True),
        Index("idx_user_archived", "user_id", "is_archived"),
    )

    def _parse_local_time(self) -> tuple[int, int]:
        """Parse update_time string (HH:MM) to local hour/minute integers."""
        if not self.update_time:
            return 0, 0
        try:
            parts = self.update_time.split(":")
            if len(parts) == 2:
                return int(parts[0]), int(parts[1])
        except (ValueError, AttributeError):
            pass
        return 0, 0

    def _get_next_scheduled_time(self, base_time: datetime) -> datetime:
        """Calculate the next scheduled time after base_time.

        All date calculations are done in local timezone (Asia/Shanghai),
        then converted to UTC for storage/comparison.

        Args:
            base_time: UTC datetime to compare against

        Returns:
            UTC datetime of next scheduled time

        """
        from zoneinfo import ZoneInfo

        # Convert base_time to local timezone for comparison
        shanghai_tz = ZoneInfo("Asia/Shanghai")
        base_local = base_time.astimezone(shanghai_tz)

        frequency = self.update_frequency or UpdateFrequency.HOURLY.value

        if frequency == UpdateFrequency.HOURLY.value:
            # Next top of the hour in local time, then convert to UTC
            next_local = (base_local + timedelta(hours=1)).replace(
                minute=0, second=0, microsecond=0
            )
            return next_local.astimezone(UTC)

        if frequency == UpdateFrequency.DAILY.value:
            # Get local hour/minute from stored time
            local_hour, local_minute = self._parse_local_time()

            # Today at scheduled time in local timezone
            scheduled_local = base_local.replace(
                hour=local_hour, minute=local_minute, second=0, microsecond=0
            )

            # If already passed today, next one is tomorrow
            if scheduled_local <= base_local:
                scheduled_local += timedelta(days=1)

            # Convert back to UTC
            return scheduled_local.astimezone(UTC)

        if frequency == UpdateFrequency.WEEKLY.value:
            # Get local hour/minute from stored time
            local_hour, local_minute = self._parse_local_time()

            # DB stores 1-7 (Mon-Sun), Python weekday is 0-6 (Mon-Sun)
            target_weekday = (
                (self.update_day_of_week - 1) if self.update_day_of_week else 0
            )

            # Today at scheduled time in local timezone
            scheduled_local = base_local.replace(
                hour=local_hour, minute=local_minute, second=0, microsecond=0
            )

            # Find days until target weekday
            days_ahead = target_weekday - base_local.weekday()
            if days_ahead < 0 or (days_ahead == 0 and scheduled_local <= base_local):
                days_ahead += 7

            # Add the days and convert to UTC
            scheduled_local += timedelta(days=days_ahead)
            return scheduled_local.astimezone(UTC)

        return base_time + timedelta(hours=1)  # Fallback

    @property
    def computed_next_update_at(self) -> datetime | None:
        """Calculate next update time based on frequency and user settings.
        Aligns to the next scheduled interval based on CURRENT time.
        """
        return self._get_next_scheduled_time(datetime.now(UTC))

    def should_update_now(self) -> bool:
        """Check if we should update now based on time passed since last fetch.
        Uses the subscription's last_fetched_at but user's update frequency.
        """
        if not self.subscription.last_fetched_at:
            return True

        # Convert naive datetime to aware datetime (assume UTC)
        from app.core.datetime_utils import ensure_timezone_aware_fetch_time

        last_fetched_aware = ensure_timezone_aware_fetch_time(
            self.subscription.last_fetched_at
        )

        # Calculate the Earliest next scheduled time AFTER the last fetch
        next_possible = self._get_next_scheduled_time(last_fetched_aware)

        # If the scheduled time has arrived or passed, we should update
        return datetime.now(UTC) >= next_possible


# ---------------------------------------------------------------------------
# Backward-compatible re-exports from media and content domains
# ---------------------------------------------------------------------------
# These allow existing code that imports from app.domains.podcast.models
# to continue working without changes.

from app.domains.content.models.conversation import (  # noqa: E402
    ConversationSession,
    PodcastConversation,
)
from app.domains.content.models.daily_report import (  # noqa: E402
    PodcastDailyReport,
    PodcastDailyReportItem,
)
from app.domains.content.models.highlight import (  # noqa: E402
    EpisodeHighlight,
    HighlightExtractionTask,
)
from app.domains.media.models.transcript import PodcastEpisodeTranscript  # noqa: E402
from app.domains.media.models.transcription_task import (  # noqa: E402
    TranscriptionStatus,
    TranscriptionStep,
    TranscriptionTask,
)


__all__ = [
    # Podcast domain
    "PodcastEpisode",
    "PodcastPlaybackState",
    "PodcastQueue",
    "PodcastQueueItem",
    "is_podcast_subscription",
    # Subscription domain (merged)
    "SubscriptionType",
    "SubscriptionStatus",
    "UpdateFrequency",
    "Subscription",
    "UserSubscription",
    # Media domain (re-exported)
    "PodcastEpisodeTranscript",
    "TranscriptionStatus",
    "TranscriptionStep",
    "TranscriptionTask",
    # Content domain (re-exported)
    "ConversationSession",
    "PodcastConversation",
    "PodcastDailyReport",
    "PodcastDailyReportItem",
    "EpisodeHighlight",
    "HighlightExtractionTask",
]
