"""Add missing indexes for join-heavy queries

Revision ID: 022
Revises: 021
Create Date: 2026-04-07

Add index on user_subscriptions.subscription_id for feed/content queries
that join on this column without a leading user_id filter.
Add index on podcast_queue_items.episode_id for episode lookup queries.
"""

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.create_index(
        "idx_user_subscriptions_subscription_id",
        "user_subscriptions",
        ["subscription_id"],
    )
    op.create_index(
        "idx_podcast_queue_items_episode_id",
        "podcast_queue_items",
        ["episode_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_podcast_queue_items_episode_id", table_name="podcast_queue_items")
    op.drop_index("idx_user_subscriptions_subscription_id", table_name="user_subscriptions")
