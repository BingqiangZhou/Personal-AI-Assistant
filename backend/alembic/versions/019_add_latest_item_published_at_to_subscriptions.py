"""add_latest_item_published_at_to_subscriptions

Revision ID: 019_add_latest_item_published_at
Revises: 018_cascade_delete_podcast_fk
Create Date: 2026-01-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '019_add_latest_item_published_at'
down_revision: Union[str, Sequence[str], None] = '018_cascade_delete_podcast_fk'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Add latest_item_published_at column to subscriptions table.

    This column stores the published timestamp of the latest item from this feed.
    It's different from last_fetched_at which tracks when we last checked the feed.
    """
    op.add_column(
        'subscriptions',
        sa.Column(
            'latest_item_published_at',
            sa.DateTime(),
            nullable=True,
            comment='Published timestamp of the latest item from this feed'
        )
    )


def downgrade() -> None:
    """Downgrade schema: Remove latest_item_published_at column from subscriptions table."""
    op.drop_column('subscriptions', 'latest_item_published_at')
