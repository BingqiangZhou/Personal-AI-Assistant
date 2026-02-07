"""convert user domain datetime columns to timezone-aware

Revision ID: 026_user_datetime_tz
Revises: 025_drop_assistant_multimedia
Create Date: 2026-02-07 19:00:00.000000

Converts all TIMESTAMP WITHOUT TIME ZONE columns in user-related tables
to TIMESTAMP WITH TIME ZONE for proper timezone handling.
"""
from typing import Sequence, Union

from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '026_user_datetime_tz'
down_revision: Union[str, Sequence[str], None] = '025_drop_assistant_multimedia'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Columns to convert: (table_name, column_name)
COLUMNS_TO_CONVERT = [
    # users table
    ('users', 'last_login_at'),
    ('users', 'created_at'),
    ('users', 'updated_at'),
    # user_sessions table
    ('user_sessions', 'expires_at'),
    ('user_sessions', 'last_activity_at'),
    ('user_sessions', 'created_at'),
    # password_resets table
    ('password_resets', 'expires_at'),
    ('password_resets', 'created_at'),
    ('password_resets', 'updated_at'),
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
