"""Convert AI model config cost and temperature columns to float

Revision ID: 021
Revises: 020
Create Date: 2026-04-07

Migrate cost_per_input_token, cost_per_output_token, and temperature
columns from VARCHAR to FLOAT in the ai_model_configs table.
"""

from alembic import op


revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE ai_model_configs "
        "ALTER COLUMN cost_per_input_token TYPE FLOAT USING cost_per_input_token::float"
    )
    op.execute(
        "ALTER TABLE ai_model_configs "
        "ALTER COLUMN cost_per_output_token TYPE FLOAT USING cost_per_output_token::float"
    )
    op.execute(
        "ALTER TABLE ai_model_configs "
        "ALTER COLUMN temperature TYPE FLOAT USING temperature::float"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE ai_model_configs "
        "ALTER COLUMN cost_per_input_token TYPE VARCHAR USING cost_per_input_token::text"
    )
    op.execute(
        "ALTER TABLE ai_model_configs "
        "ALTER COLUMN cost_per_output_token TYPE VARCHAR USING cost_per_output_token::text"
    )
    op.execute(
        "ALTER TABLE ai_model_configs "
        "ALTER COLUMN temperature TYPE VARCHAR USING temperature::text"
    )
