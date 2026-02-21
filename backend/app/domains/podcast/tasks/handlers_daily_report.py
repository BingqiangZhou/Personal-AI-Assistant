"""Handlers for daily report background tasks."""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone

from sqlalchemy import and_, select

from app.domains.podcast.services.daily_report_service import DailyReportService
from app.domains.subscription.models import (
    Subscription,
    SubscriptionStatus,
    UserSubscription,
)


logger = logging.getLogger(__name__)


async def generate_daily_reports_handler(
    session,
    target_date: date | None = None,
) -> dict:
    """Generate one daily report snapshot for each user with active subscriptions."""
    users_stmt = (
        select(UserSubscription.user_id)
        .join(Subscription, UserSubscription.subscription_id == Subscription.id)
        .where(
            and_(
                Subscription.source_type == "podcast-rss",
                Subscription.status == SubscriptionStatus.ACTIVE.value,
                UserSubscription.is_archived == False,  # noqa: E712
            )
        )
        .distinct()
    )
    user_ids = list((await session.execute(users_stmt)).scalars().all())

    success_count = 0
    failed_count = 0
    for user_id in user_ids:
        try:
            service = DailyReportService(session, user_id=user_id)
            await service.generate_daily_report(target_date=target_date)
            success_count += 1
        except Exception:
            failed_count += 1
            logger.exception("Failed to generate daily report for user=%s", user_id)
            await session.rollback()

    return {
        "status": "success",
        "processed_users": len(user_ids),
        "successful_users": success_count,
        "failed_users": failed_count,
        "report_date": target_date.isoformat() if target_date else None,
        "processed_at": datetime.now(timezone.utc).isoformat(),
    }
