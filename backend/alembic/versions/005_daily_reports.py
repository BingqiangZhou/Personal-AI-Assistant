"""add daily report snapshot tables

Revision ID: 005
Revises: 004
Create Date: 2026-02-21 00:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "podcast_daily_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("report_date", sa.Date(), nullable=False),
        sa.Column("timezone", sa.String(length=64), nullable=False, server_default="Asia/Shanghai"),
        sa.Column("schedule_time_local", sa.String(length=5), nullable=False, server_default="03:30"),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("total_items", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "report_date", name="uq_podcast_daily_reports_user_date"),
    )
    op.create_index(
        "idx_podcast_daily_reports_user_date",
        "podcast_daily_reports",
        ["user_id", "report_date"],
        unique=False,
    )
    op.create_index(
        "idx_podcast_daily_reports_generated_at",
        "podcast_daily_reports",
        ["generated_at"],
        unique=False,
    )

    op.create_table(
        "podcast_daily_report_items",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("report_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("episode_id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("episode_title_snapshot", sa.String(length=500), nullable=False),
        sa.Column("subscription_title_snapshot", sa.String(length=255), nullable=True),
        sa.Column("one_line_summary", sa.Text(), nullable=False),
        sa.Column("is_carryover", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("episode_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("episode_published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["report_id"], ["podcast_daily_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["episode_id"], ["podcast_episodes.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "user_id",
            "episode_id",
            name="uq_podcast_daily_report_items_user_episode",
        ),
    )
    op.create_index(
        "idx_podcast_daily_report_items_report_id",
        "podcast_daily_report_items",
        ["report_id"],
        unique=False,
    )
    op.create_index(
        "idx_podcast_daily_report_items_user_id",
        "podcast_daily_report_items",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "idx_podcast_daily_report_items_episode_id",
        "podcast_daily_report_items",
        ["episode_id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "idx_podcast_daily_report_items_episode_id",
        table_name="podcast_daily_report_items",
    )
    op.drop_index(
        "idx_podcast_daily_report_items_user_id",
        table_name="podcast_daily_report_items",
    )
    op.drop_index(
        "idx_podcast_daily_report_items_report_id",
        table_name="podcast_daily_report_items",
    )
    op.drop_table("podcast_daily_report_items")

    op.drop_index(
        "idx_podcast_daily_reports_generated_at",
        table_name="podcast_daily_reports",
    )
    op.drop_index(
        "idx_podcast_daily_reports_user_date",
        table_name="podcast_daily_reports",
    )
    op.drop_table("podcast_daily_reports")
