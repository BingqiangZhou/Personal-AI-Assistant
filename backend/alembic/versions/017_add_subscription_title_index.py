"""Add subscription title index for duplicate detection

Revision ID: 017_add_subscription_title_index
Revises: 016_remove_guid_use_item_link_as_unique
Create Date: 2026-01-14

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect, text


# revision identifiers, used by Alembic.
revision = '017_add_subscription_title_index'
down_revision = '016_remove_guid_use_item_link'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = inspect(conn)

    # Get existing indexes on subscriptions table
    existing_indexes = [idx['name'] for idx in inspector.get_indexes('subscriptions')]

    # Create index on title column if it doesn't exist
    index_name = 'idx_subscriptions_title'
    if index_name not in existing_indexes:
        # Create case-insensitive index for title matching
        # Using LOWER() for case-insensitive comparison
        op.execute(
            f"CREATE INDEX {index_name} ON subscriptions (LOWER(title))"
        )
        print(f"Created index: {index_name}")


def downgrade():
    conn = op.get_bind()
    inspector = inspect(conn)

    # Check if index exists before dropping
    existing_indexes = [idx['name'] for idx in inspector.get_indexes('subscriptions')]
    index_name = 'idx_subscriptions_title'

    if index_name in existing_indexes:
        op.execute(f"DROP INDEX {index_name}")
        print(f"Dropped index: {index_name}")
