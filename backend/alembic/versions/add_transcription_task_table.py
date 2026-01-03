"""Add transcription task table

Revision ID: 002_add_transcription_task_table
Revises: 001
Create Date: 2025-12-21 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '002_add_transcription_task_table'
down_revision: Union[str, None] = '001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create transcription status enum
    transcription_status_enum = sa.Enum(
        'pending', 'downloading', 'converting', 'splitting',
        'transcribing', 'merging', 'completed', 'failed', 'cancelled',
        name='transcriptionstatus'
    )
    transcription_status_enum.create(op.get_bind())

    # Create transcription_tasks table
    op.create_table(
        'transcription_tasks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('episode_id', sa.Integer(), nullable=False),
        sa.Column('status', transcription_status_enum, nullable=False),
        sa.Column('progress_percentage', sa.Float(), nullable=True, default=0.0),
        sa.Column('original_audio_url', sa.String(length=500), nullable=False),
        sa.Column('original_file_path', sa.String(length=1000), nullable=True),
        sa.Column('original_file_size', sa.Integer(), nullable=True),
        sa.Column('transcript_content', sa.Text(), nullable=True),
        sa.Column('transcript_word_count', sa.Integer(), nullable=True),
        sa.Column('transcript_duration', sa.Integer(), nullable=True),
        sa.Column('chunk_info', sa.JSON(), nullable=True, default=dict),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_code', sa.String(length=50), nullable=True),
        sa.Column('download_time', sa.Float(), nullable=True),
        sa.Column('conversion_time', sa.Float(), nullable=True),
        sa.Column('transcription_time', sa.Float(), nullable=True),
        sa.Column('chunk_size_mb', sa.Integer(), nullable=True, default=10),
        sa.Column('model_used', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['episode_id'], ['podcast_episodes.id'], ),
        sa.PrimaryKeyConstraint('id')
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
    op.drop_index(op.f('ix_transcription_created'), table_name='transcription_tasks')
    op.drop_index(op.f('ix_transcription_status'), table_name='transcription_tasks')
    op.drop_index(op.f('ix_transcription_episode'), table_name='transcription_tasks')

    # Drop table
    op.drop_table('transcription_tasks')

    # Drop enum
    sa.Enum(name='transcriptionstatus').drop(op.get_bind())