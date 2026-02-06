"""Admin API key management routes module."""

from app.admin.api.common import build_filtered_router
from app.admin.router import router as legacy_router


def _match(path: str) -> bool:
    return path.startswith("/apikeys") or path.startswith("/api/apikeys")


router = build_filtered_router(legacy_router, _match)

