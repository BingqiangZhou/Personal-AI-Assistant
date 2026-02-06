"""add subscription uniqueness and cleanup duplicate mappings

Revision ID: 023_sub_unique_cleanup
Revises: 022_sub_user_m2m
Create Date: 2026-02-06 00:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy import text


# revision identifiers, used by Alembic.
revision: str = "023_sub_unique_cleanup"
down_revision: Union[str, Sequence[str], None] = "022_sub_user_m2m"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_index(inspector: sa.Inspector, table: str, index_name: str) -> bool:
    return any(idx["name"] == index_name for idx in inspector.get_indexes(table))


def _has_unique_constraint(
    inspector: sa.Inspector,
    table: str,
    constraint_name: str,
) -> bool:
    return any(
        uc["name"] == constraint_name for uc in inspector.get_unique_constraints(table)
    )


def _has_unique_columns(
    inspector: sa.Inspector,
    table: str,
    columns: list[str],
) -> bool:
    target = set(columns)
    return any(
        set(uc.get("column_names") or []) == target
        for uc in inspector.get_unique_constraints(table)
    )


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Drop unique mapping index temporarily so canonical remap can be performed safely.
    if _has_index(inspector, "user_subscriptions", "idx_user_subscription"):
        op.drop_index("idx_user_subscription", table_name="user_subscriptions")

    # Build duplicate -> canonical mapping (canonical keeps the newest metadata row).
    conn.execute(
        text(
            """
            CREATE TEMP TABLE tmp_subscription_canonical AS
            WITH ranked AS (
                SELECT
                    id,
                    source_type,
                    source_url,
                    ROW_NUMBER() OVER (
                        PARTITION BY source_type, source_url
                        ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
                    ) AS rn,
                    FIRST_VALUE(id) OVER (
                        PARTITION BY source_type, source_url
                        ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
                    ) AS canonical_id
                FROM subscriptions
                WHERE source_type IS NOT NULL AND source_url IS NOT NULL
            )
            SELECT id AS duplicate_id, canonical_id
            FROM ranked
            WHERE rn > 1;
            """
        )
    )

    # user_subscriptions: remove rows that would conflict on remap, then remap.
    conn.execute(
        text(
            """
            DELETE FROM user_subscriptions us
            USING tmp_subscription_canonical m
            WHERE us.subscription_id = m.duplicate_id
              AND EXISTS (
                SELECT 1
                FROM user_subscriptions keep_row
                WHERE keep_row.user_id = us.user_id
                  AND keep_row.subscription_id = m.canonical_id
              );
            """
        )
    )
    conn.execute(
        text(
            """
            UPDATE user_subscriptions us
            SET subscription_id = m.canonical_id
            FROM tmp_subscription_canonical m
            WHERE us.subscription_id = m.duplicate_id;
            """
        )
    )

    # subscription_category_mappings has composite PK, so de-duplicate before remap.
    conn.execute(
        text(
            """
            DELETE FROM subscription_category_mappings scm
            USING tmp_subscription_canonical m
            WHERE scm.subscription_id = m.duplicate_id
              AND EXISTS (
                SELECT 1
                FROM subscription_category_mappings keep_row
                WHERE keep_row.subscription_id = m.canonical_id
                  AND keep_row.category_id = scm.category_id
              );
            """
        )
    )
    conn.execute(
        text(
            """
            UPDATE subscription_category_mappings scm
            SET subscription_id = m.canonical_id
            FROM tmp_subscription_canonical m
            WHERE scm.subscription_id = m.duplicate_id;
            """
        )
    )

    # Straight remaps for related tables.
    conn.execute(
        text(
            """
            UPDATE podcast_episodes pe
            SET subscription_id = m.canonical_id
            FROM tmp_subscription_canonical m
            WHERE pe.subscription_id = m.duplicate_id;
            """
        )
    )
    conn.execute(
        text(
            """
            UPDATE subscription_items si
            SET subscription_id = m.canonical_id
            FROM tmp_subscription_canonical m
            WHERE si.subscription_id = m.duplicate_id;
            """
        )
    )

    # Merge duplicate user_subscriptions after remap: prefer most complete and newest row.
    conn.execute(
        text(
            """
            WITH ranked AS (
                SELECT
                    id,
                    ROW_NUMBER() OVER (
                        PARTITION BY user_id, subscription_id
                        ORDER BY
                            (
                                CASE WHEN update_frequency IS NOT NULL THEN 1 ELSE 0 END +
                                CASE WHEN update_time IS NOT NULL THEN 1 ELSE 0 END +
                                CASE WHEN update_day_of_week IS NOT NULL THEN 1 ELSE 0 END
                            ) DESC,
                            updated_at DESC NULLS LAST,
                            created_at DESC NULLS LAST,
                            id DESC
                    ) AS rn
                FROM user_subscriptions
            )
            DELETE FROM user_subscriptions us
            USING ranked r
            WHERE us.id = r.id
              AND r.rn > 1;
            """
        )
    )

    # Remove duplicate subscription rows after all children are remapped.
    conn.execute(
        text(
            """
            DELETE FROM subscriptions s
            USING tmp_subscription_canonical m
            WHERE s.id = m.duplicate_id;
            """
        )
    )
    conn.execute(text("DROP TABLE IF EXISTS tmp_subscription_canonical;"))

    inspector = sa.inspect(conn)

    if not _has_unique_constraint(
        inspector, "subscriptions", "uq_subscriptions_source_type_source_url"
    ) and not _has_unique_columns(
        inspector, "subscriptions", ["source_type", "source_url"]
    ):
        op.create_unique_constraint(
            "uq_subscriptions_source_type_source_url",
            "subscriptions",
            ["source_type", "source_url"],
        )

    if not _has_index(inspector, "subscriptions", "idx_subscriptions_source_type_status"):
        op.create_index(
            "idx_subscriptions_source_type_status",
            "subscriptions",
            ["source_type", "status"],
            unique=False,
        )

    if not _has_index(
        inspector, "user_subscriptions", "idx_user_subscriptions_subscription_archived"
    ):
        op.create_index(
            "idx_user_subscriptions_subscription_archived",
            "user_subscriptions",
            ["subscription_id", "is_archived"],
            unique=False,
        )

    if not _has_index(
        inspector, "user_subscriptions", "idx_user_subscriptions_user_archived_updated"
    ):
        op.create_index(
            "idx_user_subscriptions_user_archived_updated",
            "user_subscriptions",
            ["user_id", "is_archived", "updated_at"],
            unique=False,
        )

    inspector = sa.inspect(conn)
    if not _has_index(inspector, "user_subscriptions", "idx_user_subscription"):
        op.create_index(
            "idx_user_subscription",
            "user_subscriptions",
            ["user_id", "subscription_id"],
            unique=True,
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if _has_index(
        inspector, "user_subscriptions", "idx_user_subscriptions_user_archived_updated"
    ):
        op.drop_index(
            "idx_user_subscriptions_user_archived_updated",
            table_name="user_subscriptions",
        )

    if _has_index(
        inspector, "user_subscriptions", "idx_user_subscriptions_subscription_archived"
    ):
        op.drop_index(
            "idx_user_subscriptions_subscription_archived",
            table_name="user_subscriptions",
        )

    if _has_index(inspector, "subscriptions", "idx_subscriptions_source_type_status"):
        op.drop_index("idx_subscriptions_source_type_status", table_name="subscriptions")

    if _has_unique_constraint(
        inspector, "subscriptions", "uq_subscriptions_source_type_source_url"
    ):
        op.drop_constraint(
            "uq_subscriptions_source_type_source_url",
            "subscriptions",
            type_="unique",
        )
