"""Report orchestrator -- daily report generation for podcast users."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from sqlalchemy import and_, select

from app.core.config import settings
from app.core.database import worker_db_session
from app.domains.podcast.services.daily_report_service import DailyReportService
from app.domains.subscription.models import (
    Subscription,
    SubscriptionStatus,
    UserSubscription,
)

from .base import BaseOrchestrator


logger = logging.getLogger(__name__)


class ReportOrchestrator(BaseOrchestrator):
    """Orchestrate daily report generation tasks."""

    async def generate_daily_reports(self, *, target_date=None) -> dict:
        """Generate daily reports for all podcast users.

        Uses concurrent processing with semaphore for rate limiting.
        Each user gets an isolated database session to prevent transaction conflicts.
        """
        batch_size = max(1, settings.TASK_ORCHESTRATION_USER_BATCH_SIZE)
        max_concurrent = min(10, batch_size)  # Limit concurrent processing
        last_user_id = 0
        processed_users = 0
        success_count = 0
        failed_count = 0

        semaphore = asyncio.Semaphore(max_concurrent)

        async def process_user_report(user_id: int) -> bool:
            """Process a single user's daily report with isolated session."""
            async with semaphore:
                try:
                    async with worker_db_session("daily-report-user") as session:
                        service = DailyReportService(session, user_id=user_id)
                        await service.generate_daily_report(target_date=target_date)
                        return True
                except Exception:
                    logger.exception(
                        "Failed to generate daily report for user=%s",
                        user_id,
                    )
                    return False

        while True:
            users_stmt = (
                select(UserSubscription.user_id)
                .join(Subscription, UserSubscription.subscription_id == Subscription.id)
                .where(
                    and_(
                        Subscription.source_type == "podcast-rss",
                        Subscription.status == SubscriptionStatus.ACTIVE.value,
                        UserSubscription.is_archived == False,  # noqa: E712
                        UserSubscription.user_id > last_user_id,
                    ),
                )
                .distinct()
                .order_by(UserSubscription.user_id.asc())
                .limit(batch_size)
            )
            user_ids = list((await self.session.execute(users_stmt)).scalars().all())
            if not user_ids:
                break

            # Process users concurrently with asyncio.gather
            results = await asyncio.gather(
                *[process_user_report(user_id) for user_id in user_ids],
                return_exceptions=True,
            )

            # Count successes and failures
            for result in results:
                if isinstance(result, Exception):
                    failed_count += 1
                elif result is True:
                    success_count += 1
                else:
                    failed_count += 1

            processed_users += len(user_ids)
            last_user_id = user_ids[-1]

        return {
            "status": "success",
            "processed_users": processed_users,
            "successful_users": success_count,
            "failed_users": failed_count,
            "report_date": target_date.isoformat() if target_date else None,
            "processed_at": datetime.now(UTC).isoformat(),
        }
