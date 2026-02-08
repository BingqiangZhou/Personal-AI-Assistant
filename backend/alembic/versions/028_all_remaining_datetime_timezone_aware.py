"""Update all remaining datetime columns to timezone-aware.

Revision ID: 028_all_remaining_datetime_timezone_aware
Revises: 027_transcription_task_datetime_timezone_aware
Create Date: 2026-02-08 18:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '028_all_remaining_datetime_tz'
down_revision: Union[str, None] = '027_transcription_tz'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Convert admin_audit_logs.created_at
    op.execute("ALTER TABLE admin_audit_logs ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert system_settings.created_at and updated_at
    op.execute("ALTER TABLE system_settings ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE system_settings ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert background_task_runs.started_at and finished_at
    op.execute("ALTER TABLE background_task_runs ALTER COLUMN started_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE background_task_runs ALTER COLUMN finished_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert podcast_episodes.published_at, last_played_at, created_at, updated_at
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN published_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN last_played_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert podcast_playback_states.last_updated_at
    op.execute("ALTER TABLE podcast_playback_states ALTER COLUMN last_updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert podcast_conversations.created_at
    op.execute("ALTER TABLE podcast_conversations ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert subscriptions.last_fetched_at, latest_item_published_at, created_at, updated_at
    op.execute("ALTER TABLE subscriptions ALTER COLUMN last_fetched_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN latest_item_published_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert user_subscriptions.created_at, updated_at
    op.execute("ALTER TABLE user_subscriptions ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE user_subscriptions ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert subscription_items.published_at, read_at, created_at, updated_at
    op.execute("ALTER TABLE subscription_items ALTER COLUMN published_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscription_items ALTER COLUMN read_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscription_items ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscription_items ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert subscription_categories.created_at, updated_at
    op.execute("ALTER TABLE subscription_categories ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")
    op.execute("ALTER TABLE subscription_categories ALTER COLUMN updated_at TYPE TIMESTAMP WITH TIME ZONE")

    # Convert subscription_category_mappings.created_at
    op.execute("ALTER TABLE subscription_category_mappings ALTER COLUMN created_at TYPE TIMESTAMP WITH TIME ZONE")


def downgrade() -> None:
    # Revert admin_audit_logs.created_at
    op.execute("ALTER TABLE admin_audit_logs ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert system_settings.created_at and updated_at
    op.execute("ALTER TABLE system_settings ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE system_settings ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert background_task_runs.started_at and finished_at
    op.execute("ALTER TABLE background_task_runs ALTER COLUMN started_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE background_task_runs ALTER COLUMN finished_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert podcast_episodes.published_at, last_played_at, created_at, updated_at
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN published_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN last_played_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE podcast_episodes ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert podcast_playback_states.last_updated_at
    op.execute("ALTER TABLE podcast_playback_states ALTER COLUMN last_updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert podcast_conversations.created_at
    op.execute("ALTER TABLE podcast_conversations ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert subscriptions.last_fetched_at, latest_item_published_at, created_at, updated_at
    op.execute("ALTER TABLE subscriptions ALTER COLUMN last_fetched_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN latest_item_published_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscriptions ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert user_subscriptions.created_at, updated_at
    op.execute("ALTER TABLE user_subscriptions ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE user_subscriptions ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert subscription_items.published_at, read_at, created_at, updated_at
    op.execute("ALTER TABLE subscription_items ALTER COLUMN published_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscription_items ALTER COLUMN read_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscription_items ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscription_items ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert subscription_categories.created_at, updated_at
    op.execute("ALTER TABLE subscription_categories ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
    op.execute("ALTER TABLE subscription_categories ALTER COLUMN updated_at TYPE TIMESTAMP WITHOUT TIME ZONE")

    # Revert subscription_category_mappings.created_at
    op.execute("ALTER TABLE subscription_category_mappings ALTER COLUMN created_at TYPE TIMESTAMP WITHOUT TIME ZONE")
