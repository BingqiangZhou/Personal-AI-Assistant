"""Add GIN indexes for JSON columns to optimize JSON path queries

Revision ID: 016
Revises: 015
Create Date: 2026-03-22 00:00:00.000000

This migration adds GIN indexes for JSON/JSONB columns to improve
performance of JSON path queries and containment operations.

Note: Uses default GIN operator class which works with both json and jsonb types.
For jsonb columns, jsonb_path_ops would be more efficient but requires ALTER COLUMN.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add GIN indexes for JSON columns using default operator class."""

    # Users table - settings and preferences JSON columns
    # Note: Using default GIN operator class (works with json type)
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_settings_gin
        ON users USING GIN (settings);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_users_preferences_gin
        ON users USING GIN (preferences);
        """
    )

    # Podcast episodes - metadata column (stored as 'metadata' in DB)
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_episodes_metadata_gin
        ON podcast_episodes USING GIN ("metadata");
        """
    )

    # Transcription tasks - chunk_info column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transcription_tasks_chunk_info_gin
        ON transcription_tasks USING GIN (chunk_info);
        """
    )

    # AI model configs - extra_config column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_ai_model_configs_extra_config_gin
        ON ai_model_configs USING GIN (extra_config);
        """
    )

    # Admin audit logs - details column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_admin_audit_logs_details_gin
        ON admin_audit_logs USING GIN (details);
        """
    )

    # Background task runs - metadata column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_background_task_runs_metadata_gin
        ON background_task_runs USING GIN ("metadata");
        """
    )

    # System settings - value column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_system_settings_value_gin
        ON system_settings USING GIN (value);
        """
    )

    # Episode highlights - topic_tags column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_episode_highlights_topic_tags_gin
        ON episode_highlights USING GIN (topic_tags);
        """
    )

    # User sessions - device_info column
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_user_sessions_device_info_gin
        ON user_sessions USING GIN (device_info);
        """
    )


def downgrade() -> None:
    """Remove JSON GIN indexes."""

    op.execute("DROP INDEX IF EXISTS idx_users_settings_gin;")
    op.execute("DROP INDEX IF EXISTS idx_users_preferences_gin;")
    op.execute("DROP INDEX IF EXISTS idx_podcast_episodes_metadata_gin;")
    op.execute("DROP INDEX IF EXISTS idx_transcription_tasks_chunk_info_gin;")
    op.execute("DROP INDEX IF EXISTS idx_ai_model_configs_extra_config_gin;")
    op.execute("DROP INDEX IF EXISTS idx_admin_audit_logs_details_gin;")
    op.execute("DROP INDEX IF EXISTS idx_background_task_runs_metadata_gin;")
    op.execute("DROP INDEX IF EXISTS idx_system_settings_value_gin;")
    op.execute("DROP INDEX IF EXISTS idx_episode_highlights_topic_tags_gin;")
    op.execute("DROP INDEX IF EXISTS idx_user_sessions_device_info_gin;")
