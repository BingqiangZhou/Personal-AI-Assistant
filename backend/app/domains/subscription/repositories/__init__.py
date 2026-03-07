"""Subscription repository exports."""

from .mutation import SubscriptionMutationRepository
from .query import SubscriptionQueryRepository


class SubscriptionRepository(
    SubscriptionMutationRepository,
    SubscriptionQueryRepository,
):
    """Compatibility facade composed from focused query and mutation repositories."""


__all__ = ["SubscriptionRepository"]
