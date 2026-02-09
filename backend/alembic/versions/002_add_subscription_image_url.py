"""Add image_url column to subscriptions table

Revision ID: 002_add_subscription_image_url
Revises: 719fde19cbcc
Create Date: 2026-02-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '002_add_subscription_image_url'
down_revision: Union[str, Sequence[str], None] = '719fde19cbcc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add image_url column to subscriptions table."""
    op.add_column('subscriptions', sa.Column('image_url', sa.String(500), nullable=True))


def downgrade() -> None:
    """Remove image_url column from subscriptions table."""
    op.drop_column('subscriptions', 'image_url')
