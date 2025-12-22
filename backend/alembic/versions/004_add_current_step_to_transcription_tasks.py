"""Add current_step field to transcription_tasks

Revision ID: 005_current_step
Revises: 004_transcription_summary
Create Date: 2024-12-23

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Enum


# revision identifiers, used by Alembic.
revision = '005_current_step'
down_revision = '004_transcription_summary'
branch_labels = None
depends_on = None


def upgrade():
    # Step 1: Drop and recreate TranscriptionStep enum with lowercase values
    op.execute('DROP TYPE IF EXISTS transcriptionstep CASCADE')

    transcription_step_enum = Enum(
        'not_started',
        'downloading',
        'converting',
        'splitting',
        'transcribing',
        'merging',
        name='transcriptionstep'
    )
    transcription_step_enum.create(op.get_bind(), checkfirst=False)

    # Step 2: Add current_step column (nullable first, then update and make NOT NULL)
    op.add_column(
        'transcription_tasks',
        sa.Column(
            'current_step',
            sa.Enum('not_started', 'downloading', 'converting', 'splitting', 'transcribing', 'merging',
                     name='transcriptionstep', create_type=False),
            nullable=True
        )
    )

    # Step 3: Set default value for existing rows
    op.execute("UPDATE transcription_tasks SET current_step = 'not_started' WHERE current_step IS NULL")

    # Step 4: Make the column NOT NULL with a default
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN current_step SET NOT NULL")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN current_step SET DEFAULT 'not_started'")

    # Step 5: Fix TranscriptionStatus enum - first drop the index that references status
    op.execute("DROP INDEX IF EXISTS idx_transcription_tasks_summary_status")

    # Convert status to VARCHAR
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status TYPE VARCHAR(20) USING status::text")

    # Step 6: Update existing status values to lowercase and map to new simplified statuses
    op.execute("UPDATE transcription_tasks SET status = LOWER(status)")

    # Map old step statuses to new simplified statuses
    op.execute("UPDATE transcription_tasks SET status = 'in_progress' WHERE status IN ('downloading', 'converting', 'splitting', 'transcribing', 'merging')")

    # Step 7: Drop and recreate TranscriptionStatus enum with lowercase values
    op.execute('DROP TYPE IF EXISTS transcriptionstatus CASCADE')

    transcription_status_enum = Enum(
        'pending',
        'in_progress',
        'completed',
        'failed',
        'cancelled',
        name='transcriptionstatus'
    )
    transcription_status_enum.create(op.get_bind(), checkfirst=False)

    # Step 8: Convert status column back to enum type
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status TYPE transcriptionstatus USING status::transcriptionstatus")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status SET DEFAULT 'pending'")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status SET NOT NULL")

    # Step 9: Recreate the index with lowercase status value
    op.execute("CREATE INDEX idx_transcription_tasks_summary_status ON transcription_tasks (summary_content, status) WHERE summary_content IS NULL AND status = 'completed'")


def downgrade():
    # Step 0: Drop the index first
    op.execute("DROP INDEX IF EXISTS idx_transcription_tasks_summary_status")

    # Step 1: Remove current_step column
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN current_step DROP DEFAULT")
    op.drop_column('transcription_tasks', 'current_step')

    # Step 2: Convert status back to VARCHAR
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status TYPE VARCHAR(20) USING status::text")

    # Step 3: Drop simplified enum and recreate old-style enum
    op.execute('DROP TYPE IF EXISTS transcriptionstatus CASCADE')

    old_transcription_status_enum = Enum(
        'pending',
        'downloading',
        'converting',
        'splitting',
        'transcribing',
        'merging',
        'completed',
        'failed',
        'cancelled',
        name='transcriptionstatus'
    )
    old_transcription_status_enum.create(op.get_bind(), checkfirst=False)

    # Step 4: Convert status back to old enum type
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status TYPE transcriptionstatus USING status::transcriptionstatus")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status SET DEFAULT 'pending'")
    op.execute("ALTER TABLE transcription_tasks ALTER COLUMN status SET NOT NULL")

    # Step 5: Recreate the index with uppercase status value (old enum)
    op.execute("CREATE INDEX idx_transcription_tasks_summary_status ON transcription_tasks (summary_content, status) WHERE summary_content IS NULL AND status = 'COMPLETED'")

    # Step 6: Drop TranscriptionStep enum
    op.execute('DROP TYPE IF EXISTS transcriptionstep CASCADE')
