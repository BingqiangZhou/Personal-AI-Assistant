"""add pg_trgm extension and high-impact query indexes

Revision ID: 006
Revises: 005
Create Date: 2026-02-22 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm;")

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_episodes_subscription_published_id
        ON podcast_episodes (subscription_id, published_at DESC, id DESC);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_playback_states_user_updated_episode
        ON podcast_playback_states (user_id, last_updated_at DESC, episode_id);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_subscription_items_subscription_read
        ON subscription_items (subscription_id, read_at);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_subscriptions_source_status_created
        ON subscriptions (source_type, status, created_at DESC);
        """
    )

    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_episodes_title_trgm
        ON podcast_episodes USING gin (title gin_trgm_ops);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_episodes_description_trgm
        ON podcast_episodes USING gin (description gin_trgm_ops);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_episodes_ai_summary_trgm
        ON podcast_episodes USING gin (ai_summary gin_trgm_ops);
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP INDEX IF EXISTS idx_podcast_episodes_ai_summary_trgm;")
    op.execute("DROP INDEX IF EXISTS idx_podcast_episodes_description_trgm;")
    op.execute("DROP INDEX IF EXISTS idx_podcast_episodes_title_trgm;")

    op.execute("DROP INDEX IF EXISTS idx_subscriptions_source_status_created;")
    op.execute("DROP INDEX IF EXISTS idx_subscription_items_subscription_read;")
    op.execute("DROP INDEX IF EXISTS idx_podcast_playback_states_user_updated_episode;")
    op.execute("DROP INDEX IF EXISTS idx_podcast_episodes_subscription_published_id;")
