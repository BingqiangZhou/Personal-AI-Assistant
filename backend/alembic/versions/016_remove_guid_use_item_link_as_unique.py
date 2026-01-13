"""Remove guid column, use item_link as unique constraint

Revision ID: 016
Revises: 015
Create Date: 2026-01-14

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '016_remove_guid_use_item_link'
down_revision = '015_add_system_settings'
branch_labels = None
depends_on = None


def upgrade():
    """Remove guid column and make item_link unique and NOT NULL.

    First, fill any NULL item_link values with audio_url as fallback.
    Then drop the guid column and its index.
    Finally, make item_link unique and NOT NULL.
    """
    conn = op.get_bind()

    # Step 1: Fill NULL item_link values with audio_url as fallback
    conn.execute(sa.text("""
        UPDATE podcast_episodes
        SET item_link = COALESCE(item_link, audio_url)
        WHERE item_link IS NULL
    """))

    # Step 2: Drop the unique index on guid
    op.drop_index('ix_podcast_episodes_guid', table_name='podcast_episodes')

    # Step 3: Drop the guid column
    op.drop_column('podcast_episodes', 'guid')

    # Step 4: Drop the old index on item_link
    op.drop_index('idx_podcast_episodes_item_link', table_name='podcast_episodes')

    # Step 5: Remove duplicate item_link values
    # First, delete playback_states for duplicate episodes (keep max id)
    # Then delete transcription_tasks for duplicate episodes
    # Finally, delete the duplicate episodes
    conn.execute(sa.text("""
        DELETE FROM podcast_playback_states
        WHERE episode_id IN (
            SELECT id FROM podcast_episodes
            WHERE id NOT IN (
                SELECT max(id) FROM podcast_episodes GROUP BY item_link
            )
        )
    """))

    conn.execute(sa.text("""
        DELETE FROM transcription_tasks
        WHERE episode_id IN (
            SELECT id FROM podcast_episodes
            WHERE id NOT IN (
                SELECT max(id) FROM podcast_episodes GROUP BY item_link
            )
        )
    """))

    conn.execute(sa.text("""
        DELETE FROM podcast_episodes
        WHERE id NOT IN (
            SELECT max(id) FROM podcast_episodes GROUP BY item_link
        )
    """))

    # Step 6: Make item_link NOT NULL
    conn.execute(sa.text("""
        ALTER TABLE podcast_episodes
        ALTER COLUMN item_link SET NOT NULL
    """))

    # Step 7: Create unique index on item_link
    op.create_index(
        'idx_podcast_episodes_item_link',
        'podcast_episodes',
        ['item_link'],
        unique=True
    )


def downgrade():
    """Restore guid column and remove item_link unique constraint.

    This is a simplified downgrade - it recreates guid from item_link.
    """
    conn = op.get_bind()

    # Step 1: Drop the unique index on item_link
    op.drop_index('idx_podcast_episodes_item_link', table_name='podcast_episodes')

    # Step 2: Make item_link nullable again
    conn.execute(sa.text("""
        ALTER TABLE podcast_episodes
        ALTER COLUMN item_link DROP NOT NULL
    """))

    # Step 3: Recreate non-unique index on item_link
    op.create_index(
        'idx_podcast_episodes_item_link',
        'podcast_episodes',
        ['item_link'],
        unique=False
    )

    # Step 4: Add guid column as nullable first
    op.add_column(
        'podcast_episodes',
        sa.Column('guid', sa.String(length=500), nullable=True)
    )

    # Step 5: Fill guid with item_link values (or audio_url as fallback)
    conn.execute(sa.text("""
        UPDATE podcast_episodes
        SET guid = COALESCE(item_link, audio_url, 'fallback-' || id::text)
        WHERE guid IS NULL
    """))

    # Step 6: Make guid NOT NULL
    conn.execute(sa.text("""
        ALTER TABLE podcast_episodes
        ALTER COLUMN guid SET NOT NULL
    """))

    # Step 7: Create unique index on guid
    op.create_index(
        'ix_podcast_episodes_guid',
        'podcast_episodes',
        ['guid'],
        unique=True
    )
