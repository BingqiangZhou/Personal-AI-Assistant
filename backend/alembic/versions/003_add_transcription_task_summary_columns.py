"""add transcription task summary columns

Revision ID: 004_transcription_summary
Revises: 003_episode_image
Create Date: 2024-12-21 15:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '004_transcription_summary'
down_revision = '003_episode_image'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add summary columns to transcription_tasks table
    # These columns are needed for the AI summary generation feature
    # that integrates with the transcription process

    op.add_column('transcription_tasks', sa.Column(
        'summary_content',
        sa.Text(),
        nullable=True,
        comment='AI generated summary content'
    ))

    op.add_column('transcription_tasks', sa.Column(
        'summary_model_used',
        sa.String(length=100),
        nullable=True,
        comment='AI model used for summary generation'
    ))

    op.add_column('transcription_tasks', sa.Column(
        'summary_word_count',
        sa.Integer(),
        nullable=True,
        comment='Word count of the generated summary'
    ))

    op.add_column('transcription_tasks', sa.Column(
        'summary_processing_time',
        sa.Float(),
        nullable=True,
        comment='Time taken to generate summary in seconds'
    ))

    op.add_column('transcription_tasks', sa.Column(
        'summary_error_message',
        sa.Text(),
        nullable=True,
        comment='Error message if summary generation failed'
    ))

    # Create index for faster queries on summary status
    op.create_index(
        'idx_transcription_tasks_summary_status',
        'transcription_tasks',
        ['summary_content', 'status'],
        postgresql_where=sa.text("summary_content IS NULL AND status = 'COMPLETED'")
    )


def downgrade() -> None:
    # Drop indexes
    op.drop_index(
        'idx_transcription_tasks_summary_status',
        table_name='transcription_tasks'
    )

    # Drop columns
    op.drop_column('transcription_tasks', 'summary_error_message')
    op.drop_column('transcription_tasks', 'summary_processing_time')
    op.drop_column('transcription_tasks', 'summary_word_count')
    op.drop_column('transcription_tasks', 'summary_model_used')
    op.drop_column('transcription_tasks', 'summary_content')