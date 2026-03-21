"""add composite index for highlight date range queries

Revision ID: 013
Revises: 012
Create Date: 2026-03-21 00:00:00.000000

This migration adds a composite index on (status, created_at) for the
episode_highlights table to optimize date range queries that filter by status.
Without this index, queries using created_at filters would cause full table scans.

"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add composite index for highlight queries."""
    # Composite index for status + created_at DESC to optimize:
    # 1. Date range queries (get_highlights with date_from/date_to)
    # 2. Date-ordered queries (get_highlight_dates orders by date DESC)
    op.execute(
        """
        CREATE INDEX idx_episode_highlight_status_created
        ON episode_highlights (status, created_at DESC);
        """
    )


def downgrade() -> None:
    """Remove composite index."""
    op.execute("DROP INDEX IF EXISTS idx_episode_highlight_status_created;")
