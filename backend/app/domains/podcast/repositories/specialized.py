"""Specialized repository entrypoints for podcast services and tasks."""

from __future__ import annotations

from app.domains.podcast.repositories.analytics import PodcastAnalyticsRepositoryMixin
from app.domains.podcast.repositories.base import BasePodcastRepository
from app.domains.podcast.repositories.content import PodcastContentRepositoryMixin
from app.domains.podcast.repositories.feed import PodcastFeedRepositoryMixin
from app.domains.podcast.repositories.playback_queue import (
    PodcastPlaybackQueueRepositoryMixin,
)


class PodcastEpisodeRepository(
    BasePodcastRepository,
    PodcastContentRepositoryMixin,
    PodcastFeedRepositoryMixin,
    PodcastPlaybackQueueRepositoryMixin,
    PodcastAnalyticsRepositoryMixin,
):
    """Repository used by episode-facing application services."""


class PodcastSubscriptionRepository(
    BasePodcastRepository,
    PodcastContentRepositoryMixin,
    PodcastFeedRepositoryMixin,
    PodcastPlaybackQueueRepositoryMixin,
):
    """Repository used by subscription management flows."""


class PodcastPlaybackRepository(
    BasePodcastRepository,
    PodcastContentRepositoryMixin,
    PodcastPlaybackQueueRepositoryMixin,
    PodcastAnalyticsRepositoryMixin,
):
    """Repository used by playback preference and history flows."""


class PodcastQueueRepository(
    BasePodcastRepository,
    PodcastContentRepositoryMixin,
    PodcastPlaybackQueueRepositoryMixin,
):
    """Repository used by queue mutation flows."""


class PodcastSearchRepository(
    BasePodcastRepository,
    PodcastAnalyticsRepositoryMixin,
    PodcastPlaybackQueueRepositoryMixin,
):
    """Repository used by search and recommendations."""


class PodcastStatsRepository(
    BasePodcastRepository,
    PodcastAnalyticsRepositoryMixin,
):
    """Repository used by stats aggregation flows."""


class PodcastSummaryRepository(
    BasePodcastRepository,
    PodcastContentRepositoryMixin,
):
    """Repository used by summary orchestration flows."""
