"""Create base tables

Revision ID: 000
Revises:
Create Date: 2025-01-01 00:00:00.000000

This migration creates the base tables required for the application:
- users and user_sessions (authentication)
- password_resets (password reset flow)
- subscriptions, user_subscriptions, subscription_items (subscription management)
- subscription_categories, subscription_category_mappings (category management)

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '000'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all base tables."""
    # Create users table
    op.create_table('users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('username', sa.String(length=100), nullable=True),
        sa.Column('account_name', sa.String(length=255), nullable=True),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('avatar_url', sa.String(length=500), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('is_superuser', sa.Boolean(), nullable=True),
        sa.Column('is_verified', sa.Boolean(), nullable=True),
        sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('settings', postgresql.JSON(), nullable=True),
        sa.Column('preferences', postgresql.JSON(), nullable=True),
        sa.Column('api_key', sa.String(length=255), nullable=True),
        sa.Column('totp_secret', sa.String(length=32), nullable=True),
        sa.Column('is_2fa_enabled', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    op.create_index('ix_users_username', 'users', ['username'], unique=True)
    op.create_index('ix_users_id', 'users', ['id'])
    op.create_index('idx_email_status', 'users', ['email', 'status'])
    op.create_index('idx_username_status', 'users', ['username', 'status'])

    # Create user_sessions table
    op.create_table('user_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('session_token', sa.String(length=255), nullable=False),
        sa.Column('refresh_token', sa.String(length=255), nullable=True),
        sa.Column('device_info', postgresql.JSON(), nullable=True),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_activity_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_sessions_id', 'user_sessions', ['id'])
    op.create_index('ix_user_sessions_session_token', 'user_sessions', ['session_token'], unique=True)
    op.create_index('ix_user_sessions_refresh_token', 'user_sessions', ['refresh_token'], unique=True)
    op.create_index('idx_user_active', 'user_sessions', ['user_id', 'is_active'])
    op.create_index('idx_user_sessions_token_expires', 'user_sessions', ['session_token', 'expires_at'])

    # Create password_resets table
    op.create_table('password_resets',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_used', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_password_resets_id', 'password_resets', ['id'])
    op.create_index('ix_password_resets_token', 'password_resets', ['token'], unique=True)
    op.create_index('idx_email_token', 'password_resets', ['email', 'token'])
    op.create_index('idx_password_reset_token_expires', 'password_resets', ['token', 'expires_at'])
    op.create_index('idx_email_unused', 'password_resets', ['email', 'is_used'])

    # Create subscriptions table
    op.create_table('subscriptions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('source_type', sa.String(length=50), nullable=False),
        sa.Column('source_url', sa.String(length=500), nullable=False),
        sa.Column('config', postgresql.JSON(), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=True),
        sa.Column('last_fetched_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('latest_item_published_at', sa.DateTime(timezone=True), nullable=True,
                   comment='Published timestamp of the latest item from this feed'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('fetch_interval', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_subscriptions_id', 'subscriptions', ['id'])
    op.create_index('idx_source_type', 'subscriptions', ['source_type'])
    op.create_index('idx_source_url', 'subscriptions', ['source_url'])

    # Create user_subscriptions table (many-to-many mapping)
    op.create_table('user_subscriptions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('update_frequency', sa.String(length=10), nullable=True,
                   comment='Update frequency type: HOURLY, DAILY, WEEKLY'),
        sa.Column('update_time', sa.String(length=5), nullable=True,
                   comment='Update time in HH:MM format (24-hour)'),
        sa.Column('update_day_of_week', sa.Integer(), nullable=True,
                   comment='Day of week for WEEKLY frequency (1=Monday, 7=Sunday)'),
        sa.Column('is_archived', sa.Boolean(), nullable=True,
                   comment='User has archived this subscription'),
        sa.Column('is_pinned', sa.Boolean(), nullable=True,
                   comment='User has pinned this subscription'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_user_subscriptions_id', 'user_subscriptions', ['id'])
    op.create_index('idx_user_subscription', 'user_subscriptions', ['user_id', 'subscription_id'], unique=True)
    op.create_index('idx_user_archived', 'user_subscriptions', ['user_id', 'is_archived'])

    # Create subscription_items table
    op.create_table('subscription_items',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('external_id', sa.String(length=255), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('author', sa.String(length=255), nullable=True),
        sa.Column('source_url', sa.String(length=500), nullable=True),
        sa.Column('image_url', sa.String(length=500), nullable=True),
        sa.Column('tags', postgresql.JSON(), nullable=True),
        sa.Column('metadata', postgresql.JSON(), nullable=True),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('bookmarked', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_subscription_items_id', 'subscription_items', ['id'])
    op.create_index('idx_subscription_external', 'subscription_items', ['subscription_id', 'external_id'])
    op.create_index('idx_published_at', 'subscription_items', ['published_at'])
    op.create_index('idx_read_at', 'subscription_items', ['read_at'])
    op.create_index('idx_bookmarked', 'subscription_items', ['bookmarked'])

    # Create subscription_categories table
    op.create_table('subscription_categories',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('color', sa.String(length=7), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_subscription_categories_id', 'subscription_categories', ['id'])
    op.create_index('idx_user_category', 'subscription_categories', ['user_id', 'name'])

    # Create subscription_category_mappings table (many-to-many mapping)
    op.create_table('subscription_category_mappings',
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('category_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['category_id'], ['subscription_categories.id']),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id']),
        sa.PrimaryKeyConstraint('subscription_id', 'category_id')
    )


def downgrade() -> None:
    """Drop all base tables in reverse order."""
    # Drop tables with FK constraints first
    op.drop_table('subscription_category_mappings')
    op.drop_table('subscription_items')
    op.drop_table('user_subscriptions')
    op.drop_table('subscriptions')
    op.drop_table('password_resets')
    op.drop_table('user_sessions')
    op.drop_table('subscription_categories')
    op.drop_table('users')
