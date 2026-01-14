"""add_cascade_delete_to_podcast_foreign_keys

Revision ID: 5abb1e7ec4ac
Revises: 017_add_subscription_title_index
Create Date: 2026-01-14 13:16:09.930400

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = '018_cascade_delete_podcast_fk'
down_revision: Union[str, Sequence[str], None] = '017_add_subscription_title_index'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema: Add ON DELETE CASCADE to podcast episode foreign keys.

    This fixes the subscription deletion error where deleting a subscription
    fails because transcription_tasks and other related tables have foreign key
    constraints without CASCADE DELETE.

    When a subscription is deleted:
    - podcast_episodes are cascade deleted via SQLAlchemy relationship
    - But related tables (transcription_tasks, playback_states, conversations)
      need database-level CASCADE DELETE to avoid NOT NULL constraint violations
    """
    conn = op.get_bind()

    # 1. Fix podcast_playback_states.episode_id foreign key
    # Drop existing constraint and recreate with ON DELETE CASCADE
    conn.execute(text("""
        ALTER TABLE podcast_playback_states
        DROP CONSTRAINT IF EXISTS podcast_playback_states_episode_id_fkey
    """))
    conn.execute(text("""
        ALTER TABLE podcast_playback_states
        ADD CONSTRAINT podcast_playback_states_episode_id_fkey
        FOREIGN KEY (episode_id)
        REFERENCES podcast_episodes(id)
        ON DELETE CASCADE
    """))

    # 2. Fix transcription_tasks.episode_id foreign key
    conn.execute(text("""
        ALTER TABLE transcription_tasks
        DROP CONSTRAINT IF EXISTS transcription_tasks_episode_id_fkey
    """))
    conn.execute(text("""
        ALTER TABLE transcription_tasks
        ADD CONSTRAINT transcription_tasks_episode_id_fkey
        FOREIGN KEY (episode_id)
        REFERENCES podcast_episodes(id)
        ON DELETE CASCADE
    """))

    # 3. Fix podcast_conversations.episode_id foreign key
    conn.execute(text("""
        ALTER TABLE podcast_conversations
        DROP CONSTRAINT IF EXISTS podcast_conversations_episode_id_fkey
    """))
    conn.execute(text("""
        ALTER TABLE podcast_conversations
        ADD CONSTRAINT podcast_conversations_episode_id_fkey
        FOREIGN KEY (episode_id)
        REFERENCES podcast_episodes(id)
        ON DELETE CASCADE
    """))


def downgrade() -> None:
    """Downgrade schema: Remove ON DELETE CASCADE from foreign keys.

    Reverts the foreign key constraints to their original state without CASCADE.
    """
    conn = op.get_bind()

    # 1. Revert podcast_playback_states.episode_id foreign key
    conn.execute(text("""
        ALTER TABLE podcast_playback_states
        DROP CONSTRAINT IF EXISTS podcast_playback_states_episode_id_fkey
    """))
    conn.execute(text("""
        ALTER TABLE podcast_playback_states
        ADD CONSTRAINT podcast_playback_states_episode_id_fkey
        FOREIGN KEY (episode_id)
        REFERENCES podcast_episodes(id)
    """))

    # 2. Revert transcription_tasks.episode_id foreign key
    conn.execute(text("""
        ALTER TABLE transcription_tasks
        DROP CONSTRAINT IF EXISTS transcription_tasks_episode_id_fkey
    """))
    conn.execute(text("""
        ALTER TABLE transcription_tasks
        ADD CONSTRAINT transcription_tasks_episode_id_fkey
        FOREIGN KEY (episode_id)
        REFERENCES podcast_episodes(id)
    """))

    # 3. Revert podcast_conversations.episode_id foreign key
    conn.execute(text("""
        ALTER TABLE podcast_conversations
        DROP CONSTRAINT IF EXISTS podcast_conversations_episode_id_fkey
    """))
    conn.execute(text("""
        ALTER TABLE podcast_conversations
        ADD CONSTRAINT podcast_conversations_episode_id_fkey
        FOREIGN KEY (episode_id)
        REFERENCES podcast_episodes(id)
    """))
