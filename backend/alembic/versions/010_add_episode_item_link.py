"""add item_link to podcast_episodes

Revision ID: 010
Revises: 009_add_download_method
Create Date: 2026-01-03

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '010_add_episode_item_link'
down_revision = '009_add_download_method'
branch_labels = None
depends_on = None


def upgrade():
    """Add item_link column to podcast_episodes table"""
    # Add item_link column as nullable first
    op.add_column(
        'podcast_episodes',
        sa.Column(
            'item_link',
            sa.String(500),
            nullable=True
        )
    )

    # Create index for faster lookups
    op.create_index(
        'idx_podcast_episodes_item_link',
        'podcast_episodes',
        ['item_link']
    )


def downgrade():
    """Remove item_link column from podcast_episodes table"""
    # Drop index
    op.drop_index(
        'idx_podcast_episodes_item_link',
        table_name='podcast_episodes'
    )

    # Drop column
    op.drop_column('podcast_episodes', 'item_link')
