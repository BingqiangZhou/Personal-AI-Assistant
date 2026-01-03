"""remove download_method from transcription_tasks

Revision ID: 011_remove_download_method
Revises: 010_add_episode_item_link
Create Date: 2026-01-03

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '011_remove_download_method'
down_revision = '010_add_episode_item_link'
branch_labels = None
depends_on = None


def upgrade():
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


def downgrade():
    """Add download_method column back to transcription_tasks table"""
    # For rollback, add the column back
    op.add_column(
        'transcription_tasks',
        sa.Column(
            'download_method',
            sa.String(20),
            nullable=False,
            server_default='aiohttp'
        )
    )

    # Create check constraint
    op.execute(
        "ALTER TABLE transcription_tasks "
        "ADD CONSTRAINT chk_transcription_tasks_download_method "
        "CHECK (download_method IN ('aiohttp', 'browser', 'none'))"
    )

    # Create index
    op.create_index(
        'idx_transcription_tasks_download_method',
        'transcription_tasks',
        ['download_method']
    )
