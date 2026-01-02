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
    # Add download_method column with check constraint
    op.add_column(
        'transcription_tasks',
        sa.Column(
            'download_method',
            sa.String(20),
            nullable=False,
            server_default='aiohttp'
        )
    )

    # Create check constraint for valid values
    op.execute(
        "ALTER TABLE transcription_tasks "
        "ADD CONSTRAINT chk_transcription_tasks_download_method "
        "CHECK (download_method IN ('aiohttp', 'browser', 'none'))"
    )

    # Create index for analytics
    op.create_index(
        'idx_transcription_tasks_download_method',
        'transcription_tasks',
        ['download_method']
    )


def downgrade():
    """Remove download_method column from transcription_tasks table"""
    # Drop index
    op.drop_index(
        'idx_transcription_tasks_download_method',
        table_name='transcription_tasks'
    )

    # Drop check constraint (PostgreSQL specific)
    op.execute(
        "ALTER TABLE transcription_tasks "
        "DROP CONSTRAINT IF EXISTS chk_transcription_tasks_download_method"
    )

    # Drop column
    op.drop_column('transcription_tasks', 'download_method')
