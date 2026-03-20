"""add episode highlights tables

Revision ID: 012
Revises: 011
Create Date: 2026-03-20 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op
from sqlalchemy import JSON


# revision identifiers, used by Alembic.
revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""

    # Create highlight_extraction_tasks table
    op.execute(
        """
        CREATE TYPE highlightextractionstatus AS ENUM (
            'pending',
            'in_progress',
            'completed',
            'failed'
        );
        """
    )

    op.execute(
        """
        CREATE TABLE highlight_extraction_tasks (
            id SERIAL PRIMARY KEY,
            episode_id INTEGER NOT NULL UNIQUE REFERENCES podcast_episodes(id) ON DELETE CASCADE,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            progress FLOAT DEFAULT 0.0,
            highlights_count INTEGER DEFAULT 0,
            processing_time FLOAT,
            error_message TEXT,
            model_used VARCHAR(100),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            started_at TIMESTAMP WITH TIME ZONE,
            completed_at TIMESTAMP WITH TIME ZONE
        );
        """
    )

    # Create episode_highlights table
    op.execute(
        """
        CREATE TABLE episode_highlights (
            id SERIAL PRIMARY KEY,
            episode_id INTEGER NOT NULL REFERENCES podcast_episodes(id) ON DELETE CASCADE,
            original_text TEXT NOT NULL,
            context_before TEXT,
            context_after TEXT,
            insight_score FLOAT NOT NULL,
            novelty_score FLOAT NOT NULL,
            actionability_score FLOAT NOT NULL,
            overall_score FLOAT NOT NULL,
            speaker_hint VARCHAR(200),
            timestamp_hint VARCHAR(50),
            topic_tags JSONB DEFAULT '[]',
            model_used VARCHAR(100),
            extraction_task_id INTEGER REFERENCES highlight_extraction_tasks(id) ON DELETE SET NULL,
            is_user_favorited BOOLEAN DEFAULT FALSE,
            status VARCHAR(20) DEFAULT 'active',
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
        """
    )

    # Create indexes for highlight_extraction_tasks
    op.execute(
        """
        CREATE INDEX idx_highlight_extraction_episode
        ON highlight_extraction_tasks (episode_id);
        """
    )

    op.execute(
        """
        CREATE INDEX idx_highlight_extraction_status
        ON highlight_extraction_tasks (status);
        """
    )

    op.execute(
        """
        CREATE INDEX idx_highlight_extraction_created
        ON highlight_extraction_tasks (created_at);
        """
    )

    # Create indexes for episode_highlights
    op.execute(
        """
        CREATE INDEX idx_episode_highlight_episode
        ON episode_highlights (episode_id);
        """
    )

    op.execute(
        """
        CREATE INDEX idx_episode_highlight_status
        ON episode_highlights (status);
        """
    )

    op.execute(
        """
        CREATE INDEX idx_episode_highlight_overall_score
        ON episode_highlights (overall_score);
        """
    )

    op.execute(
        """
        CREATE INDEX idx_episode_highlight_favorited
        ON episode_highlights (is_user_favorited);
        """
    )

    op.execute(
        """
        CREATE INDEX idx_episode_highlight_created
        ON episode_highlights (created_at);
        """
    )


def downgrade() -> None:
    """Downgrade schema."""

    # Drop indexes
    op.execute("DROP INDEX IF EXISTS idx_episode_highlight_created;")
    op.execute("DROP INDEX IF EXISTS idx_episode_highlight_favorited;")
    op.execute("DROP INDEX IF EXISTS idx_episode_highlight_overall_score;")
    op.execute("DROP INDEX IF EXISTS idx_episode_highlight_status;")
    op.execute("DROP INDEX IF EXISTS idx_episode_highlight_episode;")
    op.execute("DROP INDEX IF EXISTS idx_highlight_extraction_created;")
    op.execute("DROP INDEX IF EXISTS idx_highlight_extraction_status;")
    op.execute("DROP INDEX IF EXISTS idx_highlight_extraction_episode;")

    # Drop tables
    op.execute("DROP TABLE IF EXISTS episode_highlights;")
    op.execute("DROP TABLE IF EXISTS highlight_extraction_tasks;")

    # Drop enum type
    op.execute("DROP TYPE IF EXISTS highlightextractionstatus;")
