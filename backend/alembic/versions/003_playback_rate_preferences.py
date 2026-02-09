"""add playback rate preferences and constraints

Revision ID: 003
Revises: 002
Create Date: 2026-02-09 21:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # users.default_playback_rate
    op.add_column(
        "users",
        sa.Column("default_playback_rate", sa.Float(), nullable=True, server_default="1.0"),
    )
    op.execute(
        "UPDATE users "
        "SET default_playback_rate = LEAST(3.0, GREATEST(0.5, COALESCE(default_playback_rate, 1.0)))"
    )
    op.alter_column(
        "users",
        "default_playback_rate",
        existing_type=sa.Float(),
        nullable=False,
        server_default="1.0",
    )
    op.create_check_constraint(
        "ck_users_default_playback_rate_range",
        "users",
        "default_playback_rate >= 0.5 AND default_playback_rate <= 3.0",
    )

    # user_subscriptions.playback_rate_preference
    op.add_column(
        "user_subscriptions",
        sa.Column("playback_rate_preference", sa.Float(), nullable=True),
    )
    op.execute(
        "UPDATE user_subscriptions "
        "SET playback_rate_preference = LEAST(3.0, GREATEST(0.5, playback_rate_preference)) "
        "WHERE playback_rate_preference IS NOT NULL"
    )
    op.create_check_constraint(
        "ck_user_subscriptions_playback_rate_preference_range",
        "user_subscriptions",
        "playback_rate_preference IS NULL OR "
        "(playback_rate_preference >= 0.5 AND playback_rate_preference <= 3.0)",
    )

    # podcast_playback_states.playback_rate
    op.execute(
        "UPDATE podcast_playback_states "
        "SET playback_rate = LEAST(3.0, GREATEST(0.5, COALESCE(playback_rate, 1.0)))"
    )
    op.alter_column(
        "podcast_playback_states",
        "playback_rate",
        existing_type=sa.Float(),
        nullable=False,
        server_default="1.0",
    )
    op.create_check_constraint(
        "ck_podcast_playback_states_playback_rate_range",
        "podcast_playback_states",
        "playback_rate >= 0.5 AND playback_rate <= 3.0",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint(
        "ck_podcast_playback_states_playback_rate_range",
        "podcast_playback_states",
        type_="check",
    )
    op.alter_column(
        "podcast_playback_states",
        "playback_rate",
        existing_type=sa.Float(),
        nullable=True,
        server_default=None,
    )

    op.drop_constraint(
        "ck_user_subscriptions_playback_rate_preference_range",
        "user_subscriptions",
        type_="check",
    )
    op.drop_column("user_subscriptions", "playback_rate_preference")

    op.drop_constraint(
        "ck_users_default_playback_rate_range",
        "users",
        type_="check",
    )
    op.drop_column("users", "default_playback_rate")
