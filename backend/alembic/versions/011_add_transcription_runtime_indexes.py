"""add transcription runtime indexes

Revision ID: 011
Revises: 010
Create Date: 2026-03-10 00:00:01.000000
"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transcription_status_updated
        ON transcription_tasks (status, updated_at DESC);
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_transcription_status_created
        ON transcription_tasks (status, created_at DESC);
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP INDEX IF EXISTS idx_transcription_status_created;")
    op.execute("DROP INDEX IF EXISTS idx_transcription_status_updated;")
