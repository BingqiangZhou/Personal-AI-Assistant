"""Admin route snapshot checks."""

from app.main import app


def _route_paths() -> set[str]:
    return {route.path for route in app.routes}


def test_admin_routes_snapshot() -> None:
    paths = _route_paths()

    expected_paths = {
        "/super/",
        "/super/setup",
        "/super/login",
        "/super/logout",
        "/super/login/2fa",
        "/super/2fa/setup",
        "/super/2fa/verify",
        "/super/2fa/disable",
        "/super/apikeys",
        "/super/apikeys/test",
        "/super/apikeys/create",
        "/super/apikeys/{key_id}/toggle",
        "/super/apikeys/{key_id}/edit",
        "/super/apikeys/{key_id}/delete",
        "/super/api/apikeys/export/json",
        "/super/api/apikeys/import/json",
        "/super/subscriptions",
        "/super/subscriptions/update-frequency",
        "/super/subscriptions/{sub_id}/edit",
        "/super/subscriptions/test-url",
        "/super/subscriptions/test-all",
        "/super/subscriptions/{sub_id}/delete",
        "/super/subscriptions/{sub_id}/refresh",
        "/super/subscriptions/batch/refresh",
        "/super/subscriptions/batch/toggle",
        "/super/subscriptions/batch/delete",
        "/super/api/subscriptions/export/opml",
        "/super/api/subscriptions/import/opml",
        "/super/audit-logs",
        "/super/users",
        "/super/users/{user_id}/toggle",
        "/super/users/{user_id}/reset-password",
        "/super/settings",
        "/super/settings/api/audio",
        "/super/settings/frequency",
        "/super/settings/api/security",
        "/super/settings/api/storage/info",
        "/super/settings/api/storage/cleanup/config",
        "/super/settings/api/storage/cleanup/execute",
    }

    assert expected_paths.issubset(paths)

