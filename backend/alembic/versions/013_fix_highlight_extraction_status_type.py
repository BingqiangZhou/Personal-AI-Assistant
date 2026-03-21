"""fix highlight_extraction_tasks status column type

Revision ID: 013
Revises: 012
Create Date: 2026-03-21 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Fix status column type from VARCHAR to enum."""

    # Alter column type from VARCHAR to enum
    op.execute(
        """
        ALTER TABLE highlight_extraction_tasks
        ALTER COLUMN status TYPE highlightextractionstatus
        USING status::highlightextractionstatus
        """
    )


def downgrade() -> None:
    """Revert status column type to VARCHAR."""

    # Revert to VARCHAR
    op.execute(
        """
        ALTER TABLE highlight_extraction_tasks
        ALTER COLUMN status TYPE VARCHAR(20)
        USING status::VARCHAR(20)
        """
    )
