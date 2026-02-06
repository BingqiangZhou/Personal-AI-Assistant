"""Admin subscription route module."""

from app.admin.routes._legacy_impl import router as legacy_router
from app.admin.routes._shared import build_filtered_router


def _match(path: str) -> bool:
    return path.startswith("/subscriptions") or path.startswith("/api/subscriptions")


router = build_filtered_router(legacy_router, _match)

