"""Admin user and audit routes module."""

from app.admin.api.common import build_filtered_router
from app.admin.router import router as legacy_router


def _match(path: str) -> bool:
    return path.startswith("/users") or path.startswith("/audit-logs")


router = build_filtered_router(legacy_router, _match)

