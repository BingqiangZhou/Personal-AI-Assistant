"""Create podcast tables

Revision ID: 001
Revises:
Create Date: 2025-12-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = '000'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create podcast_episodes table
    op.create_table('podcast_episodes',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('guid', sa.String(length=500), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=False),
        sa.Column('audio_url', sa.String(length=500), nullable=False),
        sa.Column('audio_duration', sa.Integer(), nullable=True),
        sa.Column('audio_file_size', sa.Integer(), nullable=True),
        sa.Column('transcript_url', sa.String(length=500), nullable=True),
        sa.Column('transcript_content', sa.Text(), nullable=True),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('summary_version', sa.String(length=50), nullable=True),
        sa.Column('ai_confidence_score', sa.Float(), nullable=True),
        sa.Column('play_count', sa.Integer(), nullable=True),
        sa.Column('last_played_at', sa.DateTime(), nullable=True),
        sa.Column('season', sa.Integer(), nullable=True),
        sa.Column('episode_number', sa.Integer(), nullable=True),
        sa.Column('explicit', sa.Boolean(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['subscription_id'], ['subscriptions.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_podcast_subscription', 'podcast_episodes', ['subscription_id'])
    op.create_index('idx_podcast_status', 'podcast_episodes', ['status'])
    op.create_index('idx_podcast_published', 'podcast_episodes', ['published_at'])
    op.create_index(op.f('ix_podcast_episodes_guid'), 'podcast_episodes', ['guid'], unique=True)

    # Create podcast_playback_states table
    op.create_table('podcast_playback_states',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('episode_id', sa.Integer(), nullable=False),
        sa.Column('current_position', sa.Integer(), nullable=True),
        sa.Column('is_playing', sa.Boolean(), nullable=True),
        sa.Column('playback_rate', sa.Float(), nullable=True),
        sa.Column('last_updated_at', sa.DateTime(), nullable=True),
        sa.Column('timestamp', sa.DateTime(), nullable=True),
        sa.Column('play_count', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['episode_id'], ['podcast_episodes.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_user_episode_unique', 'podcast_playback_states', ['user_id', 'episode_id'], unique=True)


def downgrade() -> None:
    # Drop podcast_playback_states table
    op.drop_index('idx_user_episode_unique', table_name='podcast_playback_states')
    op.drop_table('podcast_playback_states')

    # Drop podcast_episodes table
    op.drop_index(op.f('ix_podcast_episodes_guid'), table_name='podcast_episodes')
    op.drop_index('idx_podcast_published', table_name='podcast_episodes')
    op.drop_index('idx_podcast_status', table_name='podcast_episodes')
    op.drop_index('idx_podcast_subscription', table_name='podcast_episodes')
    op.drop_table('podcast_episodes')