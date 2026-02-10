"""Add conversation sessions support

Revision ID: 004
Revises: 003
Create Date: 2026-02-10

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create conversation_sessions table
    op.create_table(
        "conversation_sessions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "episode_id",
            sa.Integer(),
            sa.ForeignKey("podcast_episodes.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("title", sa.String(255), default="默认对话"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_session_episode_user",
        "conversation_sessions",
        ["episode_id", "user_id"],
    )
    op.create_index(
        "idx_session_created",
        "conversation_sessions",
        ["created_at"],
    )

    # Add session_id column to podcast_conversations
    op.add_column(
        "podcast_conversations",
        sa.Column(
            "session_id",
            sa.Integer(),
            sa.ForeignKey("conversation_sessions.id", ondelete="CASCADE"),
            nullable=True,
        ),
    )
    op.create_index(
        "idx_conversation_session",
        "podcast_conversations",
        ["session_id"],
    )

    # Data migration: create default sessions for existing conversations
    conn = op.get_bind()

    # Find all unique episode_id + user_id combos with existing conversations
    existing = conn.execute(
        sa.text(
            "SELECT DISTINCT episode_id, user_id FROM podcast_conversations"
        )
    ).fetchall()

    for episode_id, user_id in existing:
        # Create a default session
        result = conn.execute(
            sa.text(
                "INSERT INTO conversation_sessions (episode_id, user_id, title) "
                "VALUES (:episode_id, :user_id, :title) RETURNING id"
            ),
            {"episode_id": episode_id, "user_id": user_id, "title": "默认对话"},
        )
        session_id = result.scalar()

        # Update existing conversations to point to this session
        conn.execute(
            sa.text(
                "UPDATE podcast_conversations SET session_id = :session_id "
                "WHERE episode_id = :episode_id AND user_id = :user_id"
            ),
            {
                "session_id": session_id,
                "episode_id": episode_id,
                "user_id": user_id,
            },
        )


def downgrade() -> None:
    op.drop_index("idx_conversation_session", table_name="podcast_conversations")
    op.drop_column("podcast_conversations", "session_id")
    op.drop_index("idx_session_created", table_name="conversation_sessions")
    op.drop_index("idx_session_episode_user", table_name="conversation_sessions")
    op.drop_table("conversation_sessions")
