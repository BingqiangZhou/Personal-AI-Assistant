"""Add subscription schedule configuration fields

Revision ID: 008
Revises: 007_add_podcast_conversations
Create Date: 2025-12-25

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '008_schedule_fields'
down_revision = '007_add_podcast_conversations'
branch_labels = None
depends_on = None


def upgrade():
    """Add schedule configuration fields to subscriptions table."""
    # Add update_frequency column with default 'HOURLY'
    op.add_column(
        'subscriptions',
        sa.Column(
            'update_frequency',
            sa.String(10),
            nullable=False,
            server_default='HOURLY',
            comment='Update frequency type: HOURLY, DAILY, WEEKLY'
        )
    )

    # Add update_time column
    op.add_column(
        'subscriptions',
        sa.Column(
            'update_time',
            sa.String(5),
            nullable=True,
            comment='Update time in HH:MM format (24-hour)'
        )
    )

    # Add update_day_of_week column
    op.add_column(
        'subscriptions',
        sa.Column(
            'update_day_of_week',
            sa.Integer,
            nullable=True,
            comment='Day of week for WEEKLY frequency (1=Monday, 7=Sunday)'
        )
    )

    # Update existing subscriptions to have HOURLY frequency by default
    op.execute("""
        UPDATE subscriptions
        SET update_frequency = 'HOURLY'
        WHERE update_frequency IS NULL
    """)


def downgrade():
    """Remove schedule configuration fields from subscriptions table."""
    op.drop_column('subscriptions', 'update_day_of_week')
    op.drop_column('subscriptions', 'update_time')
    op.drop_column('subscriptions', 'update_frequency')
