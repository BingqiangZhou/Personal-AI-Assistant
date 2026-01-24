"""
Date and time utility functions.

This module provides utility functions for handling datetime operations,
including timezone management, formatting, and conversions.
日期时间工具函数
"""

from datetime import datetime, timezone
from typing import Optional, Union
import logging

logger = logging.getLogger(__name__)


def remove_timezone(dt: Optional[datetime]) -> Optional[datetime]:
    """
    Remove timezone information from a datetime object.

    This is useful when working with databases that don't support
    timezone-aware datetime objects (e.g., SQLite or certain PostgreSQL configurations).

    Args:
        dt: Datetime object, may or may not have timezone info

    Returns:
        Datetime object without timezone info, or None if input is None

    Examples:
        >>> dt = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        >>> remove_timezone(dt)
        datetime.datetime(2024, 1, 1, 12, 0)

        >>> remove_timezone(None)
        None
    """
    if dt is None:
        return None

    if dt.tzinfo is not None:
        return dt.replace(tzinfo=None)

    return dt


def ensure_timezone_aware(
    dt: Optional[datetime],
    tz: timezone = timezone.utc
) -> Optional[datetime]:
    """
    Ensure a datetime object is timezone-aware.

    Args:
        dt: Datetime object
        tz: Timezone to use (default: UTC)

    Returns:
        Timezone-aware datetime object, or None if input is None
    """
    if dt is None:
        return None

    if dt.tzinfo is None:
        return dt.replace(tzinfo=tz)

    return dt


def to_isoformat(dt: Optional[datetime]) -> Optional[str]:
    """
    Convert datetime to ISO format string, handling None gracefully.

    Args:
        dt: Datetime object

    Returns:
        ISO format string, or None if input is None
    """
    if dt is None:
        return None

    return dt.isoformat()


def parse_isoformat(dt_str: Optional[str]) -> Optional[datetime]:
    """
    Parse ISO format string to datetime, handling None gracefully.

    Args:
        dt_str: ISO format datetime string

    Returns:
        Datetime object, or None if input is None or invalid
    """
    if dt_str is None:
        return None

    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except (ValueError, AttributeError) as e:
        logger.warning(f"Failed to parse datetime string '{dt_str}': {e}")
        return None


def format_datetime(
    dt: Optional[datetime],
    format_str: str = "%Y-%m-%d %H:%M:%S"
) -> Optional[str]:
    """
    Format datetime to string using specified format.

    Args:
        dt: Datetime object
        format_str: strftime format string

    Returns:
        Formatted string, or None if input is None
    """
    if dt is None:
        return None

    return dt.strftime(format_str)


def get_current_timestamp() -> datetime:
    """
    Get current timestamp as timezone-aware datetime.

    Returns:
        Current datetime in UTC
    """
    return datetime.now(timezone.utc)


def calculate_age(dt: datetime) -> Optional[float]:
    """
    Calculate the age of a datetime in seconds.

    Args:
        dt: Datetime object (should be in the past)

    Returns:
        Age in seconds, or None if dt is None or in the future
    """
    if dt is None:
        return None

    now = get_current_timestamp()
    delta = now - dt

    # Handle timezone-aware datetimes
    if dt.tzinfo is None:
        dt = ensure_timezone_aware(dt)
    if now.tzinfo is None:
        now = ensure_timezone_aware(now)

    # Only return positive ages
    if delta.total_seconds() < 0:
        return None

    return delta.total_seconds()


def is_expired(dt: datetime, max_age_seconds: float) -> bool:
    """
    Check if a datetime is expired based on max age.

    Args:
        dt: Datetime to check
        max_age_seconds: Maximum allowed age in seconds

    Returns:
        True if datetime is older than max_age, False otherwise
    """
    age = calculate_age(dt)
    if age is None:
        return False

    return age > max_age_seconds


def sanitize_published_date(
    published_at: Optional[datetime]
) -> Optional[datetime]:
    """
    Sanitize podcast episode published date by removing timezone.

    This is a common operation for podcast feeds to ensure compatibility
    with databases that don't support timezone-aware datetimes.

    Args:
        published_at: Published date from podcast feed

    Returns:
        Datetime without timezone info, or None

    Examples:
        >>> dt = datetime(2024, 1, 1, 12, 0, tzinfo=timezone.utc)
        >>> sanitize_published_date(dt)
        datetime.datetime(2024, 1, 1, 12, 0)
    """
    return remove_timezone(published_at)


def bulk_remove_timezone(
    dates: list[Optional[datetime]]
) -> list[Optional[datetime]]:
    """
    Remove timezone from multiple datetime objects.

    Args:
        dates: List of datetime objects

    Returns:
        List of datetime objects without timezone
    """
    return [remove_timezone(dt) for dt in dates]
