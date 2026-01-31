"""Refactor subscription-user relationship to many-to-many

Revision ID: 022_sub_user_m2m
Revises: 021_drop_unused_tables
Create Date: 2026-01-31 00:00:00.000000

This migration refactors the subscription-user relationship from one-to-many
to many-to-many, allowing multiple users to subscribe to the same subscription
source (e.g., RSS feed) without duplicating the subscription metadata.

Changes:
1. Create user_subscriptions mapping table
2. Migrate existing data from subscriptions.user_id to user_subscriptions
3. Move update_frequency, update_time, update_day_of_week to user_subscriptions
4. Drop user_id and update columns from subscriptions table
5. Make subscription_categories.user_id nullable for shared categories
6. Update indexes

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '022_sub_user_m2m'
down_revision: Union[str, Sequence[str], None] = '021_drop_unused_tables'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to many-to-many relationship."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Step 1: Create user_subscriptions table
    op.create_table('user_subscriptions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('update_frequency', sa.String(length=10), nullable=True),
        sa.Column('update_time', sa.String(length=5), nullable=True, comment='Update time in HH:MM format (24-hour)'),
        sa.Column('update_day_of_week', sa.Integer(), nullable=True, comment='Day of week for WEEKLY frequency (1=Monday, 7=Sunday)'),
        sa.Column('is_archived', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('is_pinned', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.text('NOW()')),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Step 2: Migrate existing data from subscriptions to user_subscriptions
    conn.execute(text("""
        INSERT INTO user_subscriptions (
            user_id, subscription_id,
            update_frequency, update_time, update_day_of_week,
            created_at, updated_at
        )
        SELECT
            user_id, id,
            update_frequency, update_time, update_day_of_week,
            created_at, updated_at
        FROM subscriptions
        WHERE user_id IS NOT NULL
    """))

    # Step 3: Create unique index on user_subscriptions
    op.create_index('idx_user_subscription', 'user_subscriptions', ['user_id', 'subscription_id'], unique=True)
    op.create_index('idx_user_archived', 'user_subscriptions', ['user_id', 'is_archived'])

    # Step 4: Add new index to subscriptions (source_url for deduplication)
    existing_indexes = [idx['name'] for idx in inspector.get_indexes('subscriptions')]
    if 'idx_source_url' not in existing_indexes:
        op.create_index('idx_source_url', 'subscriptions', ['source_url'])

    # Step 5: Drop old indexes from subscriptions that reference user_id
    for index_name in ['idx_user_status', 'idx_user_latest_published']:
        if index_name in existing_indexes:
            op.drop_index(index_name, table_name='subscriptions')

    # Step 6: Drop user_id and update columns from subscriptions
    columns = [col['name'] for col in inspector.get_columns('subscriptions')]
    for column in ['user_id', 'update_frequency', 'update_time', 'update_day_of_week']:
        if column in columns:
            op.drop_column('subscriptions', column)

    # Step 7: Make subscription_categories.user_id nullable
    categories_columns = [col['name'] for col in inspector.get_columns('subscription_categories')]
    if 'user_id' in categories_columns:
        # First drop the existing index
        category_indexes = [idx['name'] for idx in inspector.get_indexes('subscription_categories')]
        if 'idx_user_category' in category_indexes:
            op.drop_index('idx_user_category', table_name='subscription_categories')

        # Alter column to nullable
        op.execute("ALTER TABLE subscription_categories ALTER COLUMN user_id DROP NOT NULL")

        # Recreate index as non-unique (allows NULL user_id for shared categories)
        op.create_index('idx_user_category', 'subscription_categories', ['user_id', 'name'])


def downgrade() -> None:
    """Rollback to one-to-many relationship."""
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Step 1: Re-add columns to subscriptions
    columns = [col['name'] for col in inspector.get_columns('subscriptions')]

    if 'user_id' not in columns:
        op.add_column('subscriptions', sa.Column('user_id', sa.Integer(), nullable=True))
    if 'update_frequency' not in columns:
        op.add_column('subscriptions', sa.Column('update_frequency', sa.String(length=10), nullable=True))
    if 'update_time' not in columns:
        op.add_column('subscriptions', sa.Column('update_time', sa.String(length=5), nullable=True))
    if 'update_day_of_week' not in columns:
        op.add_column('subscriptions', sa.Column('update_day_of_week', sa.Integer(), nullable=True))

    # Step 2: Migrate data back from user_subscriptions to subscriptions
    # Take the first user_id for each subscription
    conn.execute(text("""
        UPDATE subscriptions s
        SET
            user_id = us.user_id,
            update_frequency = us.update_frequency,
            update_time = us.update_time,
            update_day_of_week = us.update_day_of_week
        FROM (
            SELECT DISTINCT ON (subscription_id)
                subscription_id, user_id,
                update_frequency, update_time, update_day_of_week
            FROM user_subscriptions
            ORDER BY subscription_id, id
        ) us
        WHERE s.id = us.subscription_id
    """))

    # Step 3: Make user_id NOT NULL
    conn.execute(text("UPDATE subscriptions SET user_id = 1 WHERE user_id IS NULL"))
    op.execute("ALTER TABLE subscriptions ALTER COLUMN user_id SET NOT NULL")

    # Step 4: Drop user_subscriptions table and indexes
    op.drop_index('idx_user_archived', table_name='user_subscriptions')
    op.drop_index('idx_user_subscription', table_name='user_subscriptions')
    op.drop_table('user_subscriptions')

    # Step 5: Recreate old indexes on subscriptions
    existing_indexes = [idx['name'] for idx in inspector.get_indexes('subscriptions')]
    if 'idx_user_status' not in existing_indexes:
        op.create_index('idx_user_status', 'subscriptions', ['user_id', 'status'])
    if 'idx_user_latest_published' not in existing_indexes:
        op.create_index('idx_user_latest_published', 'subscriptions', ['user_id', 'latest_item_published_at'])

    # Step 6: Make subscription_categories.user_id NOT NULL again
    op.execute("ALTER TABLE subscription_categories ALTER COLUMN user_id SET NOT NULL")
