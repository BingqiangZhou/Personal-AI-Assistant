"""Add index on podcast_conversations.parent_message_id

Revision ID: 018
Revises: 017
Create Date: 2026-04-05 00:00:00.000000

This migration adds an index on parent_message_id in podcast_conversations
to optimize tree-traversal queries for threaded conversations.
"""

from collections.abc import Sequence

from alembic import op


revision: str = "018"
down_revision: str | None = "017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add index on podcast_conversations.parent_message_id."""
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_conversation_parent
        ON podcast_conversations (parent_message_id)
        """
    )


def downgrade() -> None:
    """Drop index on podcast_conversations.parent_message_id."""
    op.execute("DROP INDEX IF EXISTS idx_conversation_parent")
