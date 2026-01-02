"""Add episode image field

Revision ID: 002
Revises: 001
Create Date: 2025-12-20 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003_episode_image'
down_revision: Union[str, None] = '002_add_transcription_task_table'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add image_url column to podcast_episodes table
    op.add_column('podcast_episodes', sa.Column('image_url', sa.String(length=500), nullable=True))

    # Create index for faster queries
    op.create_index('idx_podcast_episode_image', 'podcast_episodes', ['image_url'])


def downgrade() -> None:
    # Drop index
    op.drop_index('idx_podcast_episode_image', table_name='podcast_episodes')

    # Remove image_url column
    op.drop_column('podcast_episodes', 'image_url')