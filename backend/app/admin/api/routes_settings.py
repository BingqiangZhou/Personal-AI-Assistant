"""Admin settings routes module."""

from app.admin.api.common import build_filtered_router
from app.admin.router import router as legacy_router


def _match(path: str) -> bool:
    return path.startswith("/settings")


router = build_filtered_router(legacy_router, _match)

