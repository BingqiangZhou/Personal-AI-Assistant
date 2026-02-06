"""Admin setup/auth routes module."""

from app.admin.api.common import build_filtered_router
from app.admin.router import router as legacy_router


def _match(path: str) -> bool:
    return path in {
        "/setup",
        "/login",
        "/logout",
        "/login/2fa",
        "/2fa/setup",
        "/2fa/verify",
        "/2fa/disable",
        "/",
    }


router = build_filtered_router(legacy_router, _match)

