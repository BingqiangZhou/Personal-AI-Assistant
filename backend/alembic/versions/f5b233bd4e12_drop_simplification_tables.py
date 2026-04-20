"""drop_simplification_tables

Revision ID: f5b233bd4e12
Revises: 024
Create Date: 2026-04-20 22:41:58.487094

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f5b233bd4e12'
down_revision: Union[str, Sequence[str], None] = '024'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Drop tables removed during single-user simplification."""
    op.drop_table("background_task_runs")
    op.drop_table("password_resets")
    op.drop_table("user_sessions")
    op.drop_table("subscription_category_mappings")
    op.drop_table("subscription_categories")
    op.drop_table("subscription_items")


def downgrade() -> None:
    raise NotImplementedError("Cannot downgrade beyond simplification")
