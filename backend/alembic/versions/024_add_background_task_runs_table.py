"""add background task run table

Revision ID: 024_background_task_runs
Revises: 023_sub_unique_cleanup
Create Date: 2026-02-06 19:10:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "024_background_task_runs"
down_revision: Union[str, Sequence[str], None] = "023_sub_unique_cleanup"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "background_task_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_name", sa.String(length=255), nullable=False),
        sa.Column("queue_name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=False),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_background_task_runs_id",
        "background_task_runs",
        ["id"],
        unique=False,
    )
    op.create_index(
        "ix_background_task_runs_task_name",
        "background_task_runs",
        ["task_name"],
        unique=False,
    )
    op.create_index(
        "ix_background_task_runs_queue_name",
        "background_task_runs",
        ["queue_name"],
        unique=False,
    )
    op.create_index(
        "ix_background_task_runs_status",
        "background_task_runs",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_background_task_runs_started_at",
        "background_task_runs",
        ["started_at"],
        unique=False,
    )
    op.create_index(
        "idx_task_queue_started",
        "background_task_runs",
        ["queue_name", "started_at"],
        unique=False,
    )
    op.create_index(
        "idx_task_status_started",
        "background_task_runs",
        ["status", "started_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("idx_task_status_started", table_name="background_task_runs")
    op.drop_index("idx_task_queue_started", table_name="background_task_runs")
    op.drop_index("ix_background_task_runs_started_at", table_name="background_task_runs")
    op.drop_index("ix_background_task_runs_status", table_name="background_task_runs")
    op.drop_index("ix_background_task_runs_queue_name", table_name="background_task_runs")
    op.drop_index("ix_background_task_runs_task_name", table_name="background_task_runs")
    op.drop_index("ix_background_task_runs_id", table_name="background_task_runs")
    op.drop_table("background_task_runs")

