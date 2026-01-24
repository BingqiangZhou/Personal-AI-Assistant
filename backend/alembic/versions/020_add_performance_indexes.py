"""add performance indexes

Revision ID: 020_add_performance_indexes
Revises: 019_add_latest_item_published_at
Create Date: 2026-01-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '020_add_performance_indexes'
down_revision: Union[str, Sequence[str], None] = '019_add_latest_item_published_at'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Add composite indexes for performance optimization.

    These indexes improve query performance for:
    - Fetching episodes ordered by publication date per subscription
    - Filtering episodes by status and AI summary availability
    - Optimizing subscription listing queries
    """
    # Composite index for subscription episodes: (subscription_id, published_at DESC)
    # This improves queries that fetch latest episodes for subscriptions
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_podcast_subscription_published
        ON podcast_episodes (subscription_id, published_at DESC);
    """))

    # Composite index for episode status filtering: (status, ai_summary)
    # This improves queries that filter episodes needing summaries
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_podcast_status_summary
        ON podcast_episodes (status, ai_summary)
        WHERE ai_summary IS NOT NULL;
    """))

    # Composite index for subscription status queries: (user_id, status)
    # This improves queries that filter subscriptions by user and status
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_subscription_user_status
        ON subscriptions (user_id, status)
        WHERE status IS NOT NULL;
    """))

    # Index for subscription_items: (subscription_id, published_at DESC)
    # This improves feed queries that fetch latest items
    op.execute(text("""
        CREATE INDEX IF NOT EXISTS idx_subscription_items_published
        ON subscription_items (subscription_id, published_at DESC);
    """))


def downgrade() -> None:
    """Downgrade schema: Remove performance indexes."""
    op.execute(text("DROP INDEX IF EXISTS idx_podcast_subscription_published;"))
    op.execute(text("DROP INDEX IF EXISTS idx_podcast_status_summary;"))
    op.execute(text("DROP INDEX IF NOT EXISTS idx_subscription_user_status;"))
    op.execute(text("DROP INDEX IF NOT EXISTS idx_subscription_items_published;"))
