"""ensure feed subscription/published composite index exists

Revision ID: 007
Revises: 006
Create Date: 2026-02-24 00:00:00.000000
"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_podcast_episodes_subscription_published_id
        ON podcast_episodes (subscription_id, published_at DESC, id DESC);
        """
    )


def downgrade() -> None:
    """Downgrade schema."""
    # No-op: index may have existed prior to this revision.
    return None
