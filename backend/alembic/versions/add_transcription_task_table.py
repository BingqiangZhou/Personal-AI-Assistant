"""Add transcription task table

Revision ID: 002_add_transcription_task_table
Revises: 001
Create Date: 2025-12-21 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_add_transcription_task_table'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create transcription status enum if it doesn't exist
    conn = op.get_bind()
    enum_exists = conn.execute(text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_type
            WHERE typname = 'transcriptionstatus'
        );
    """)).scalar()

    if not enum_exists:
        conn.execute(text("""
            CREATE TYPE transcriptionstatus AS ENUM (
                'pending', 'downloading', 'converting', 'splitting',
                'transcribing', 'merging', 'completed', 'failed', 'cancelled'
            );
        """))

    # Create transcription_tasks table using raw SQL for enum type
    op.execute(text("""
        CREATE TABLE IF NOT EXISTS transcription_tasks (
            id SERIAL PRIMARY KEY,
            episode_id INTEGER NOT NULL REFERENCES podcast_episodes(id),
            status transcriptionstatus NOT NULL,
            progress_percentage FLOAT DEFAULT 0.0,
            original_audio_url VARCHAR(500) NOT NULL,
            original_file_path VARCHAR(1000),
            original_file_size INTEGER,
            transcript_content TEXT,
            transcript_word_count INTEGER,
            transcript_duration INTEGER,
            chunk_info JSON DEFAULT '{}',
            error_message TEXT,
            error_code VARCHAR(50),
            download_time FLOAT,
            conversion_time FLOAT,
            transcription_time FLOAT,
            chunk_size_mb INTEGER DEFAULT 10,
            model_used VARCHAR(100),
            created_at TIMESTAMP,
            started_at TIMESTAMP,
            completed_at TIMESTAMP,
            updated_at TIMESTAMP
        );
    """))

    # Create indexes
    op.create_index(
        op.f('ix_transcription_episode'),
        'transcription_tasks',
        ['episode_id'],
        unique=True
    )
    op.create_index(
        op.f('ix_transcription_status'),
        'transcription_tasks',
        ['status'],
        unique=False
    )
    op.create_index(
        op.f('ix_transcription_created'),
        'transcription_tasks',
        ['created_at'],
        unique=False
    )

    # Create indexes
    op.create_index(
        op.f('ix_transcription_episode'),
        'transcription_tasks',
        ['episode_id'],
        unique=True
    )
    op.create_index(
        op.f('ix_transcription_status'),
        'transcription_tasks',
        ['status'],
        unique=False
    )
    op.create_index(
        op.f('ix_transcription_created'),
        'transcription_tasks',
        ['created_at'],
        unique=False
    )


def downgrade() -> None:
    # Drop indexes
    op.drop_index(op.f('ix_transcription_created'), table_name='transcription_tasks', checkfirst=True)
    op.drop_index(op.f('ix_transcription_status'), table_name='transcription_tasks', checkfirst=True)
    op.drop_index(op.f('ix_transcription_episode'), table_name='transcription_tasks', checkfirst=True)

    # Drop table
    op.execute(text("DROP TABLE IF EXISTS transcription_tasks CASCADE;"))

    # Drop enum (only if no other tables are using it)
    conn = op.get_bind()
    enum_in_use = conn.execute(text("""
        SELECT EXISTS (
            SELECT 1 FROM pg_attribute
            INNER JOIN pg_type ON pg_type.oid = pg_attribute.atttypid
            WHERE pg_type.typname = 'transcriptionstatus'
            AND pg_attribute.atttypid != 0
        );
    """)).scalar()

    if not enum_in_use:
        conn.execute(text("DROP TYPE IF EXISTS transcriptionstatus;"))