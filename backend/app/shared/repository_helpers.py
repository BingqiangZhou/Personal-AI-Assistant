"""Shared repository helper functions."""

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession


async def resolve_window_total(
    db: AsyncSession,
    rows: list[Any],
    *,
    total_index: int,
    fallback_count_query: Any,
) -> int:
    """Resolve paged total via window count with empty-page fallback.

    When using window functions for pagination (e.g., func.count().over()),
    the total is included in each row. However, if the page is empty,
    we need a fallback query to get the total count.

    Args:
        db: AsyncSession for database access
        rows: Result rows from the main query
        total_index: Index of the total count column in the result row
        fallback_count_query: SQLAlchemy query to get total count

    Returns:
        Total count of items
    """
    if rows:
        return int(rows[0][total_index] or 0)
    return int(await db.scalar(fallback_count_query) or 0)
