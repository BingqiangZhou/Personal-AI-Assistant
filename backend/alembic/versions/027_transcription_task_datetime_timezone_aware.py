"""convert transcription_task datetime columns to timezone-aware

Revision ID: 027_transcription_tz
Revises: 026_user_datetime_tz
Create Date: 2026-02-07 20:20:00.000000

Converts all TIMESTAMP WITHOUT TIME ZONE columns in transcription_tasks table
to TIMESTAMP WITH TIME ZONE for proper timezone handling.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '027_transcription_tz'
down_revision: Union[str, Sequence[str], None] = '026_user_datetime_tz'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Columns to convert: (table_name, column_name)
COLUMNS_TO_CONVERT = [
    ('transcription_tasks', 'created_at'),
    ('transcription_tasks', 'started_at'),
    ('transcription_tasks', 'completed_at'),
    ('transcription_tasks', 'updated_at'),
]


def upgrade() -> None:
    """Convert TIMESTAMP columns to TIMESTAMP WITH TIME ZONE.

    PostgreSQL will interpret existing naive timestamps as UTC when converting.
    """
    for table_name, column_name in COLUMNS_TO_CONVERT:
        op.execute(text(
            f"ALTER TABLE {table_name} "
            f"ALTER COLUMN {column_name} TYPE TIMESTAMP WITH TIME ZONE "
            f"USING {column_name} AT TIME ZONE 'UTC'"
        ))


def downgrade() -> None:
    """Revert TIMESTAMP WITH TIME ZONE back to TIMESTAMP WITHOUT TIME ZONE."""
    for table_name, column_name in COLUMNS_TO_CONVERT:
        op.execute(text(
            f"ALTER TABLE {table_name} "
            f"ALTER COLUMN {column_name} TYPE TIMESTAMP WITHOUT TIME ZONE"
        ))
