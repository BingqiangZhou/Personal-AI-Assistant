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
    # Check if column already exists, add if not
    from sqlalchemy import inspect, text
    conn = op.get_bind()
    inspector = inspect(conn)
    columns = [col['name'] for col in inspector.get_columns('podcast_episodes')]

    if 'item_link' not in columns:
        op.add_column(
            'podcast_episodes',
            sa.Column(
                'item_link',
                sa.String(500),
                nullable=True
            )
        )

    # Check if index exists before creating
    indexes = inspector.get_indexes('podcast_episodes')
    index_names = [idx['name'] for idx in indexes]

    if 'idx_podcast_episodes_item_link' not in index_names:
        op.create_index(
            'idx_podcast_episodes_item_link',
            'podcast_episodes',
            ['item_link']
        )


def downgrade():
    """Remove item_link column from podcast_episodes table"""
    # Drop index if exists
    from sqlalchemy import inspect
    conn = op.get_bind()
    inspector = inspect(conn)
    indexes = inspector.get_indexes('podcast_episodes')
    index_names = [idx['name'] for idx in indexes]

    if 'idx_podcast_episodes_item_link' in index_names:
        op.drop_index(
            'idx_podcast_episodes_item_link',
            table_name='podcast_episodes'
        )

    # Drop column if exists
    columns = [col['name'] for col in inspector.get_columns('podcast_episodes')]
    if 'item_link' in columns:
        op.drop_column('podcast_episodes', 'item_link')
