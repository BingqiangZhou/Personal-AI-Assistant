"""drop assistant and multimedia domain tables

Revision ID: 025_drop_assistant_multimedia
Revises: 024_background_task_runs
Create Date: 2026-02-06 20:00:00.000000

This migration removes database tables from the removed assistant and multimedia domains:
- Assistant domain: conversations, messages, prompt_templates, assistant_tasks, tool_calls
- Multimedia domain: media_files, processing_jobs

These domains have been removed from the codebase as they were not actively used.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '025_drop_assistant_multimedia'
down_revision: Union[str, Sequence[str], None] = '024_background_task_runs'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Tables to drop (in order to respect foreign key dependencies)
TABLES_TO_DROP = [
    # Assistant domain tables (drop tool_calls first due to FK)
    'tool_calls',
    'messages',
    'conversations',
    'prompt_templates',
    'assistant_tasks',

    # Multimedia domain tables (drop analyses first due to FK)
    'image_analyses',
    'video_analyses',
    'processing_jobs',
    'media_files',
]


def upgrade() -> None:
    """Drop assistant and multimedia domain tables from the database.

    WARNING: This migration deletes tables and their data permanently.
    Make sure to backup the database before running this migration.
    """
    connection = op.get_bind()

    for table_name in TABLES_TO_DROP:
        # Check if table exists before dropping
        result = connection.execute(text(f"""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name = '{table_name}'
            );
        """))
        exists = result.scalar()

        if exists:
            # Drop table with CASCADE to handle any remaining dependencies
            op.execute(text(f"DROP TABLE IF EXISTS {table_name} CASCADE;"))
            print(f"Dropped table: {table_name}")
        else:
            print(f"Table {table_name} does not exist, skipping")


def downgrade() -> None:
    """Recreate the dropped tables (empty structure only).

    Note: This only recreates the table structures, not the data.
    Data cannot be recovered after upgrade.
    """
    # Assistant domain tables
    op.create_table(
        'conversations',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('episode_id', sa.Integer(), sa.ForeignKey('podcast_episodes.id'), nullable=True),
        sa.Column('title', sa.String(255), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )

    op.create_table(
        'messages',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('conversation_id', sa.Integer(), sa.ForeignKey('conversations.id'), nullable=False),
        sa.Column('role', sa.String(20), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )

    op.create_table(
        'prompt_templates',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )

    op.create_table(
        'assistant_tasks',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('input_data', sa.JSON(), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )

    op.create_table(
        'tool_calls',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('message_id', sa.Integer(), sa.ForeignKey('messages.id'), nullable=False),
        sa.Column('tool_name', sa.String(100), nullable=False),
        sa.Column('tool_args', sa.JSON(), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )

    # Multimedia domain tables
    op.create_table(
        'media_files',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('filename', sa.String(255), nullable=False),
        sa.Column('file_path', sa.String(500), nullable=False),
        sa.Column('file_type', sa.String(50), nullable=False),
        sa.Column('file_size', sa.BigInteger(), nullable=True),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )

    op.create_table(
        'processing_jobs',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('media_file_id', sa.Integer(), sa.ForeignKey('media_files.id'), nullable=False),
        sa.Column('job_type', sa.String(50), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('progress', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )

    op.create_table(
        'image_analyses',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('processing_job_id', sa.Integer(), sa.ForeignKey('processing_jobs.id'), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('objects', sa.JSON(), nullable=True),
        sa.Column('faces', sa.JSON(), nullable=True),
        sa.Column('text_detected', sa.JSON(), nullable=True),
        sa.Column('emotions', sa.JSON(), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )

    op.create_table(
        'video_analyses',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('processing_job_id', sa.Integer(), sa.ForeignKey('processing_jobs.id'), nullable=False),
        sa.Column('duration', sa.Float(), nullable=False),
        sa.Column('thumbnail_path', sa.String(500), nullable=True),
        sa.Column('key_frames', sa.JSON(), nullable=True),
        sa.Column('scenes', sa.JSON(), nullable=True),
        sa.Column('objects', sa.JSON(), nullable=True),
        sa.Column('text_detected', sa.JSON(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
