"""Admin setup/auth route module."""

from app.admin.routes._legacy_impl import router as legacy_router
from app.admin.routes._shared import build_filtered_router


def _match(path: str) -> bool:
    return path in {
        "/setup",
        "/login",
        "/logout",
        "/login/2fa",
        "/2fa/setup",
        "/2fa/verify",
        "/2fa/disable",
    }


router = build_filtered_router(legacy_router, _match)

