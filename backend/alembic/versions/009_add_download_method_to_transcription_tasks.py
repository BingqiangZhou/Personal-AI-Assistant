"""add download_method to transcription_tasks

Revision ID: 009
Revises: 008
Create Date: 2026-01-03

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '009_add_download_method'
down_revision = '008_schedule_fields'
branch_labels = None
depends_on = None


def upgrade():
    """Add download_method column to transcription_tasks table"""
    from sqlalchemy import inspect, text
    conn = op.get_bind()
    inspector = inspect(conn)

    # Check if column already exists, add if not
    columns = [col['name'] for col in inspector.get_columns('transcription_tasks')]

    if 'download_method' not in columns:
        op.add_column(
            'transcription_tasks',
            sa.Column(
                'download_method',
                sa.String(20),
                nullable=False,
                server_default='aiohttp'
            )
        )
    else:
        # Column exists, check if server_default needs to be set
        # Get current column default
        current_default = conn.execute(text("""
            SELECT column_default
            FROM information_schema.columns
            WHERE table_name = 'transcription_tasks'
            AND column_name = 'download_method'
        """)).scalar()

        # Set default if not already set
        if current_default is None:
            conn.execute(text("""
                ALTER TABLE transcription_tasks
                ALTER COLUMN download_method SET DEFAULT 'aiohttp'
            """))

    # Check if constraint exists before creating
    constraints = conn.execute(text("""
        SELECT constraint_name
        FROM information_schema.table_constraints
        WHERE table_name = 'transcription_tasks'
        AND constraint_type = 'CHECK'
        AND constraint_name = 'chk_transcription_tasks_download_method'
    """)).scalar()

    if constraints is None:
        # Create check constraint for valid values
        op.execute(
            "ALTER TABLE transcription_tasks "
            "ADD CONSTRAINT chk_transcription_tasks_download_method "
            "CHECK (download_method IN ('aiohttp', 'browser', 'none'))"
        )

    # Check if index exists before creating
    indexes = inspector.get_indexes('transcription_tasks')
    index_names = [idx['name'] for idx in indexes]

    if 'idx_transcription_tasks_download_method' not in index_names:
        op.create_index(
            'idx_transcription_tasks_download_method',
            'transcription_tasks',
            ['download_method']
        )


def downgrade():
    """Remove download_method column from transcription_tasks table"""
    from sqlalchemy import inspect, text
    conn = op.get_bind()
    inspector = inspect(conn)

    # Drop index if exists
    indexes = inspector.get_indexes('transcription_tasks')
    index_names = [idx['name'] for idx in indexes]

    if 'idx_transcription_tasks_download_method' in index_names:
        op.drop_index(
            'idx_transcription_tasks_download_method',
            table_name='transcription_tasks'
        )

    # Drop check constraint if exists
    constraints = conn.execute(text("""
        SELECT constraint_name
        FROM information_schema.table_constraints
        WHERE table_name = 'transcription_tasks'
        AND constraint_type = 'CHECK'
        AND constraint_name = 'chk_transcription_tasks_download_method'
    """)).scalar()

    if constraints is not None:
        op.execute(
            "ALTER TABLE transcription_tasks "
            "DROP CONSTRAINT IF EXISTS chk_transcription_tasks_download_method"
        )

    # Drop column if exists
    columns = [col['name'] for col in inspector.get_columns('transcription_tasks')]
    if 'download_method' in columns:
        op.drop_column('transcription_tasks', 'download_method')
