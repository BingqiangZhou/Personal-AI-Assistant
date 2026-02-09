"""add podcast queue tables

Revision ID: 002
Revises: 001
Create Date: 2026-02-09 18:20:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "podcast_queues",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("current_episode_id", sa.Integer(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["current_episode_id"], ["podcast_episodes.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id"),
    )
    op.create_index(
        "idx_podcast_queue_user", "podcast_queues", ["user_id"], unique=False
    )
    op.create_index(
        op.f("ix_podcast_queues_id"), "podcast_queues", ["id"], unique=False
    )

    op.create_table(
        "podcast_queue_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("queue_id", sa.Integer(), nullable=False),
        sa.Column("episode_id", sa.Integer(), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["episode_id"], ["podcast_episodes.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["queue_id"], ["podcast_queues.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "queue_id", "episode_id", name="uq_podcast_queue_item_episode"
        ),
        sa.UniqueConstraint(
            "queue_id", "position", name="uq_podcast_queue_item_position"
        ),
    )
    op.create_index(
        "idx_podcast_queue_items_queue_position",
        "podcast_queue_items",
        ["queue_id", "position"],
        unique=False,
    )
    op.create_index(
        op.f("ix_podcast_queue_items_id"), "podcast_queue_items", ["id"], unique=False
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_podcast_queue_items_id"), table_name="podcast_queue_items")
    op.drop_index(
        "idx_podcast_queue_items_queue_position", table_name="podcast_queue_items"
    )
    op.drop_table("podcast_queue_items")

    op.drop_index(op.f("ix_podcast_queues_id"), table_name="podcast_queues")
    op.drop_index("idx_podcast_queue_user", table_name="podcast_queues")
    op.drop_table("podcast_queues")
