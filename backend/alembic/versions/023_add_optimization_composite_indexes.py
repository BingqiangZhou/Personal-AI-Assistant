"""Add composite indexes for common multi-column query patterns

Revision ID: 023
Revises: 022
Create Date: 2026-04-07

Adds composite indexes for:
- podcast_episodes: (subscription_id, published_at) — fetch recent episodes per subscription
- podcast_playback_states: (user_id, last_updated_at) — playback history by time
- subscriptions: (source_type, status) — feed refresh filtering
- transcription_tasks: (episode_id, status) — failed/cancelled task lookup
"""

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.create_index(
        "idx_episodes_subscription_published",
        "podcast_episodes",
        ["subscription_id", "published_at"],
    )
    op.create_index(
        "idx_playback_states_user_updated",
        "podcast_playback_states",
        ["user_id", "last_updated_at"],
    )
    op.create_index(
        "idx_subscriptions_source_status",
        "subscriptions",
        ["source_type", "status"],
    )
    op.create_index(
        "idx_transcription_episode_status",
        "transcription_tasks",
        ["episode_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("idx_transcription_episode_status", table_name="transcription_tasks")
    op.drop_index("idx_subscriptions_source_status", table_name="subscriptions")
    op.drop_index("idx_playback_states_user_updated", table_name="podcast_playback_states")
    op.drop_index("idx_episodes_subscription_published", table_name="podcast_episodes")
