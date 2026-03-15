"""Shared time and date utilities."""

from datetime import UTC, datetime
from zoneinfo import ZoneInfo


def to_local_timezone(
    dt: datetime | None,
    format_str: str = "%Y-%m-%d %H:%M:%S",
    timezone: str = "Asia/Shanghai",
) -> str:
    """Convert UTC datetime to local timezone and format it.

    Args:
        dt: Datetime to convert (assumed UTC if naive)
        format_str: strftime format string
        timezone: Target timezone name (default: Asia/Shanghai)

    Returns:
        Formatted local datetime string, or "-" if dt is None
    """
    if dt is None:
        return "-"
    # Ensure dt is timezone-aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    # Convert to target timezone
    local_tz = ZoneInfo(timezone)
    local_dt = dt.astimezone(local_tz)
    return local_dt.strftime(format_str)


def format_uptime(seconds: float | None) -> str:
    """Format uptime seconds to human readable string (Chinese).

    Args:
        seconds: Uptime in seconds

    Returns:
        Human readable string like "2天 5小时" or "-" if None
    """
    if seconds is None:
        return "-"
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    if days > 0:
        return f"{days}天 {hours}小时"
    if hours > 0:
        return f"{hours}小时 {minutes}分钟"
    return f"{minutes}分钟"


def format_bytes(bytes_value: int | None) -> str:
    """Format bytes to human readable string.

    Args:
        bytes_value: Size in bytes

    Returns:
        Human readable string like "1.5 GB" or "-" if None
    """
    if bytes_value is None:
        return "-"
    if bytes_value >= 1073741824:
        return f"{bytes_value / 1073741824:.1f} GB"
    if bytes_value >= 1048576:
        return f"{bytes_value / 1048576:.1f} MB"
    if bytes_value >= 1024:
        return f"{bytes_value / 1024:.1f} KB"
    return f"{bytes_value} B"


def format_number(value: int | None) -> str:
    """Format number with thousand separators.

    Args:
        value: Number to format

    Returns:
        Formatted string like "1,234,567" or "-" if None
    """
    if value is None:
        return "-"
    return f"{value:,}"
