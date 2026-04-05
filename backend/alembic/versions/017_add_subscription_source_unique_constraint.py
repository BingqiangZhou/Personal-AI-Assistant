"""Add unique constraint on subscriptions (source_url, source_type)

Revision ID: 017
Revises: 016
Create Date: 2026-04-05 00:00:00.000000

This migration adds a unique constraint on (source_url, source_type) to prevent
duplicate subscription entries with the same source URL and type.
"""

from collections.abc import Sequence

from alembic import op


revision: str = "017"
down_revision: str | None = "016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add unique constraint on subscriptions (source_url, source_type)."""
    op.create_unique_constraint(
        "uq_subscriptions_source",
        "subscriptions",
        ["source_url", "source_type"],
    )


def downgrade() -> None:
    """Drop unique constraint on subscriptions (source_url, source_type)."""
    op.drop_constraint(
        "uq_subscriptions_source",
        "subscriptions",
        type_="unique",
    )
