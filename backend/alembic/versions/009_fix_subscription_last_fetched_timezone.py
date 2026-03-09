"""Fix subscription last_fetched_at timezone awareness

Revision ID: 009
Revises: 008
Create Date: 2026-03-09
"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Convert naive last_fetched_at to timezone-aware (assume UTC).

    This migration fixes a bug where subscription.last_fetched_at was stored
    as a naive datetime, causing TypeError when compared with timezone-aware
    episode.published_at during subscription refresh tasks.

    Naive datetimes are converted assuming they are in UTC (reasonable assumption
    for this system as all timestamps are generated using datetime.now(timezone.utc)).
    """
    op.execute(
        """
        UPDATE subscriptions
        SET last_fetched_at = last_fetched_at AT TIME ZONE 'UTC'
        WHERE last_fetched_at IS NOT NULL
        AND last_fetched_at::text NOT LIKE '%+00%'
        AND last_fetched_at::text NOT LIKE '%Z%';
        """
    )


def downgrade() -> None:
    """Revert to naive datetimes.

    This downgrade removes timezone information, converting back to naive datetimes.
    Use with caution as this will re-introduce the TypeError bug.
    """
    op.execute(
        """
        UPDATE subscriptions
        SET last_fetched_at = (last_fetched_at AT TIME ZONE 'UTC')::timestamp
        WHERE last_fetched_at IS NOT NULL;
        """
    )
