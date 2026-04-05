"""Add FK constraint on user_sessions.user_id referencing users.id

Revision ID: 019
Revises: 018
Create Date: 2026-04-05 00:00:00.000000

This migration adds a foreign key constraint on user_sessions.user_id
that references users.id with CASCADE delete, ensuring session records
are cleaned up when a user is deleted.
"""

from collections.abc import Sequence

from alembic import op


revision: str = "019"
down_revision: str | None = "018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add FK constraint on user_sessions.user_id."""
    op.execute(
        """
        ALTER TABLE user_sessions
        ADD CONSTRAINT fk_user_sessions_user_id
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        """
    )


def downgrade() -> None:
    """Drop FK constraint on user_sessions.user_id."""
    op.execute(
        """
        ALTER TABLE user_sessions
        DROP CONSTRAINT IF EXISTS fk_user_sessions_user_id
        """
    )
