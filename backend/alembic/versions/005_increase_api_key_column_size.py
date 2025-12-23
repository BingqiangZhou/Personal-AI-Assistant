"""Increase api_key column size to 1000 characters

Revision ID: 006_increase_api_key_size
Revises: 005_current_step
Create Date: 2024-12-23

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '006_increase_api_key_size'
down_revision = '005_current_step'
branch_labels = None
depends_on = None


def upgrade():
    # Increase api_key column size from VARCHAR(500) to VARCHAR(1000)
    op.execute("ALTER TABLE ai_model_configs ALTER COLUMN api_key TYPE VARCHAR(1000)")


def downgrade():
    # Revert back to VARCHAR(500)
    op.execute("ALTER TABLE ai_model_configs ALTER COLUMN api_key TYPE VARCHAR(500)")
