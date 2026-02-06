"""Shared utilities for admin routes."""

from collections.abc import Callable
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import HTMLResponse
from fastapi.routing import APIRoute
from fastapi.templating import Jinja2Templates


# ==================== Migrated Routes ====================
# Routes that have been migrated to independent modules and should be excluded
MIGRATED_ROUTES = {
    "/",  # dashboard.py
    "/setup",  # setup_auth.py
    "/login",  # setup_auth.py
    "/logout",  # setup_auth.py
    "/login/2fa",  # setup_auth.py
    "/2fa/setup",  # setup_auth.py
    "/2fa/verify",  # setup_auth.py
    "/2fa/disable",  # setup_auth.py
}


# ==================== Template Setup ====================

# Setup Jinja2 templates with custom functions
_templates = None


def get_templates() -> Jinja2Templates:
    """Get configured Jinja2Templates instance (singleton)."""
    global _templates
    if _templates is None:
        _templates = Jinja2Templates(directory="app/admin/templates")
        # Add min function to template globals
        _templates.env.globals["min"] = min

        # Register custom filters
        _templates.env.filters['to_local'] = to_local_timezone
        _templates.env.filters['format_uptime'] = format_uptime
        _templates.env.filters['format_bytes'] = format_bytes
        _templates.env.filters['format_number'] = format_number
    return _templates


# Custom filter to convert UTC datetime to local timezone (Asia/Shanghai, UTC+8)
def to_local_timezone(dt: datetime, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """Convert UTC datetime to Asia/Shanghai timezone and format it."""
    if dt is None:
        return '-'
    # Ensure dt is timezone-aware (assume UTC if naive)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Convert to Asia/Shanghai timezone (UTC+8)
    from zoneinfo import ZoneInfo
    shanghai_tz = ZoneInfo('Asia/Shanghai')
    local_dt = dt.astimezone(shanghai_tz)
    return local_dt.strftime(format_str)


# Custom filter for uptime formatting
def format_uptime(seconds: float) -> str:
    """Format uptime seconds to human readable string."""
    if seconds is None:
        return '-'
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    if days > 0:
        return f"{days}天 {hours}小时"
    elif hours > 0:
        return f"{hours}小时 {minutes}分钟"
    else:
        return f"{minutes}分钟"


# Custom filter for bytes formatting
def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string."""
    if bytes_value is None:
        return '-'
    if bytes_value >= 1073741824:
        return f"{bytes_value / 1073741824:.1f} GB"
    elif bytes_value >= 1048576:
        return f"{bytes_value / 1048576:.1f} MB"
    elif bytes_value >= 1024:
        return f"{bytes_value / 1024:.1f} KB"
    else:
        return f"{bytes_value} B"


# Custom filter for number formatting
def format_number(value: int) -> str:
    """Format number with thousand separators."""
    if value is None:
        return '-'
    return f"{value:,}"


# ==================== Router Helpers ====================

def build_filtered_router(
    source_router: APIRouter,
    path_predicate: Callable[[str], bool],
) -> APIRouter:
    """Clone selected APIRoutes from a source router, excluding migrated routes."""
    router = APIRouter()
    for route in source_router.routes:
        if isinstance(route, APIRoute) and path_predicate(route.path):
            # Skip migrated routes
            if route.path in MIGRATED_ROUTES:
                continue
            router.routes.append(route)
    return router

