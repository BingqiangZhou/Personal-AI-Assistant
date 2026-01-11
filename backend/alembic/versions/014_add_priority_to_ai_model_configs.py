"""add priority to ai_model_configs

Revision ID: 014_add_priority_to_ai_model_configs
Revises: 013_add_2fa_fields_to_users_table
Create Date: 2025-01-12

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '014_add_priority_to_ai'
down_revision = '013_add_2fa_fields_to'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('ai_model_configs', sa.Column('priority', sa.Integer(), nullable=True, server_default='1', comment='优先级（数字越小优先级越高）'))


def downgrade():
    op.drop_column('ai_model_configs', 'priority')
