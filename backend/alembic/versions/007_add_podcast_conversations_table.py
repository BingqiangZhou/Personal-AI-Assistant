"""add podcast conversations table

Revision ID: 007_add_podcast_conversations
Revises: 006_increase_api_key_size
Create Date: 2025-12-25 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision = '007_add_podcast_conversations'
down_revision = '006_increase_api_key_size'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create podcast_conversations table
    # This table stores chat conversations between users and AI
    # based on podcast episode AI summaries

    # First, check if the table already exists (partial migration)
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    if 'podcast_conversations' in existing_tables:
        # Table already exists, skip creation but ensure indexes exist
        existing_indexes = [idx['name'] for idx in inspector.get_indexes('podcast_conversations')]

        if 'idx_conversation_episode' not in existing_indexes:
            op.create_index(
                'idx_conversation_episode',
                'podcast_conversations',
                ['episode_id'],
            )
        if 'idx_conversation_user' not in existing_indexes:
            op.create_index(
                'idx_conversation_user',
                'podcast_conversations',
                ['user_id'],
            )
        if 'idx_conversation_created' not in existing_indexes:
            op.create_index(
                'idx_conversation_created',
                'podcast_conversations',
                ['created_at'],
            )
        if 'idx_conversation_turn' not in existing_indexes:
            op.create_index(
                'idx_conversation_turn',
                'podcast_conversations',
                ['episode_id', 'conversation_turn'],
            )
    else:
        # Create the table if it doesn't exist
        op.create_table(
            'podcast_conversations',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('episode_id', sa.Integer(), sa.ForeignKey('podcast_episodes.id'), nullable=False),
            sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
            sa.Column('role', sa.String(length=20), nullable=False, comment='user or assistant'),
            sa.Column('content', sa.Text(), nullable=False),
            sa.Column('parent_message_id', sa.Integer(), sa.ForeignKey('podcast_conversations.id'), nullable=True),
            sa.Column('conversation_turn', sa.Integer(), default=0, nullable=False),
            sa.Column('tokens_used', sa.Integer(), nullable=True),
            sa.Column('model_used', sa.String(length=100), nullable=True),
            sa.Column('processing_time', sa.Float(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True, server_default=sa.text('CURRENT_TIMESTAMP')),
            comment='Podcast episode conversations with AI assistant'
        )

        # Create indexes for efficient queries
        op.create_index(
            'idx_conversation_episode',
            'podcast_conversations',
            ['episode_id'],
        )

        op.create_index(
            'idx_conversation_user',
            'podcast_conversations',
            ['user_id'],
        )

        op.create_index(
            'idx_conversation_created',
            'podcast_conversations',
            ['created_at'],
        )

        op.create_index(
            'idx_conversation_turn',
            'podcast_conversations',
            ['episode_id', 'conversation_turn'],
        )


def downgrade() -> None:
    # Drop indexes
    op.drop_index('idx_conversation_turn', table_name='podcast_conversations')
    op.drop_index('idx_conversation_created', table_name='podcast_conversations')
    op.drop_index('idx_conversation_user', table_name='podcast_conversations')
    op.drop_index('idx_conversation_episode', table_name='podcast_conversations')

    # Drop table
    op.drop_table('podcast_conversations')
