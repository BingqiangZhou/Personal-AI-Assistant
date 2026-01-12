"""Add system settings table

Revision ID: 015_add_system_settings_table
Revises: 014_add_priority_to_ai_model_configs
Create Date: 2025-01-12

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = '015_add_system_settings'
down_revision = '014_add_priority_to_ai'
branch_labels = None
depends_on = None


def upgrade():
    from sqlalchemy import inspect, text
    conn = op.get_bind()
    inspector = inspect(conn)

    # Check if table already exists
    existing_tables = inspector.get_table_names()

    if 'system_settings' not in existing_tables:
        op.create_table(
            'system_settings',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('key', sa.String(length=100), nullable=False, comment='Setting key'),
            sa.Column('value', postgresql.JSON(astext_type=sa.Text()), nullable=True, comment='Setting value (JSON)'),
            sa.Column('description', sa.String(length=500), nullable=True, comment='Setting description'),
            sa.Column('category', sa.String(length=50), nullable=False, server_default='general', comment='Setting category: general, audio, ai, etc.'),
            sa.Column('created_at', sa.DateTime(), nullable=True, comment='Created at'),
            sa.Column('updated_at', sa.DateTime(), nullable=True, comment='Updated at'),
            sa.PrimaryKeyConstraint('id')
        )
        op.create_index(op.f('ix_system_settings_id'), 'system_settings', ['id'], unique=False)
        op.create_index(op.f('ix_system_settings_key'), 'system_settings', ['key'], unique=True)

        # Insert default settings
        op.execute("""
            INSERT INTO system_settings (key, value, description, category, created_at, updated_at)
            VALUES
                ('audio.chunk_size_mb', '{"value": 10, "min": 5, "max": 25}', 'Audio chunk size in MB / 音频切块大小（MB）', 'audio', NOW(), NOW()),
                ('audio.max_concurrent_threads', '{"value": 4, "min": 1, "max": 16}', 'Maximum concurrent processing threads / 最大并发处理线程数', 'audio', NOW(), NOW())
        """)
    else:
        # Table exists, check and create indexes if needed
        existing_indexes = [idx['name'] for idx in inspector.get_indexes('system_settings')]

        if 'ix_system_settings_id' not in existing_indexes:
            op.create_index(op.f('ix_system_settings_id'), 'system_settings', ['id'], unique=False)

        if 'ix_system_settings_key' not in existing_indexes:
            op.create_index(op.f('ix_system_settings_key'), 'system_settings', ['key'], unique=True)


def downgrade():
    op.drop_index(op.f('ix_system_settings_key'), table_name='system_settings')
    op.drop_index(op.f('ix_system_settings_id'), table_name='system_settings')
    op.drop_table('system_settings')
