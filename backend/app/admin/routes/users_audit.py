"""Admin user and audit route module."""

from app.admin.routes._legacy_impl import router as legacy_router
from app.admin.routes._shared import build_filtered_router


def _match(path: str) -> bool:
    return path.startswith("/users") or path.startswith("/audit-logs")


router = build_filtered_router(legacy_router, _match)

