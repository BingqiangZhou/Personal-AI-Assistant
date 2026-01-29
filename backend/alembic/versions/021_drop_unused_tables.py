"""drop unused tables

Revision ID: 021_drop_unused_tables
Revises: 020_add_performance_indexes
Create Date: 2026-01-25 14:23:00.000000

This migration removes database tables that are no longer used by the application:
- Knowledge base related tables (never implemented)
- Document related tables (never implemented)
- Search history table (never implemented)
- Image/Video analysis tables (feature not implemented)
- Legacy transcription_results table (replaced by transcription_tasks)

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '021_drop_unused_tables'
down_revision: Union[str, Sequence[str], None] = '020_add_performance_indexes'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Tables to drop (in order to respect foreign key dependencies)
TABLES_TO_DROP = [
    # Document-related tables (drop mappings first due to FK constraints)
    'document_tag_mappings',
    'document_chunks',
    'documents',
    'document_tags',
    
    # Knowledge base table
    'knowledge_bases',
    
    # Search history table
    'search_history',
    
    # Unused multimedia analysis tables
    'image_analyses',
    'video_analyses',
    'transcription_results',
]


def upgrade() -> None:
    """Drop unused tables from the database.
    
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
    # knowledge_bases
    op.create_table(
        'knowledge_bases',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # document_tags
    op.create_table(
        'document_tags',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('color', sa.String(7), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    
    # documents
    op.create_table(
        'documents',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('knowledge_base_id', sa.Integer(), sa.ForeignKey('knowledge_bases.id'), nullable=True),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('file_path', sa.String(500), nullable=True),
        sa.Column('file_type', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # document_chunks
    op.create_table(
        'document_chunks',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('document_id', sa.Integer(), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('chunk_index', sa.Integer(), nullable=False),
        sa.Column('embedding', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    
    # document_tag_mappings
    op.create_table(
        'document_tag_mappings',
        sa.Column('document_id', sa.Integer(), sa.ForeignKey('documents.id'), primary_key=True),
        sa.Column('tag_id', sa.Integer(), sa.ForeignKey('document_tags.id'), primary_key=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    
    # search_history
    op.create_table(
        'search_history',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('query', sa.String(500), nullable=False),
        sa.Column('results_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
    
    # image_analyses
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
    
    # video_analyses
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
    
    # transcription_results
    op.create_table(
        'transcription_results',
        sa.Column('id', sa.Integer(), primary_key=True, index=True),
        sa.Column('processing_job_id', sa.Integer(), sa.ForeignKey('processing_jobs.id'), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('language', sa.String(10), nullable=True),
        sa.Column('segments', sa.JSON(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('keywords', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), default=sa.func.now()),
    )
