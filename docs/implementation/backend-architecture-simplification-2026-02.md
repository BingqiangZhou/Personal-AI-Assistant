# Backend Architecture Simplification (2026-02)

## Summary

This document records the aggressive backend slimming completed in three batches:

1. Remove dead code and compatibility shims.
2. Replace dual podcast task tracks with one task runtime/handler architecture.
3. Keep admin functionality intact while converting admin routing to real modules.

## Public Interface Status

- API prefix remains `/api/v1`.
- Podcast subscription entry remains `/api/v1/subscriptions/podcasts*`.
- Legacy `/api/v1/podcasts/subscriptions*` path family is not restored.
- Admin endpoint prefix remains `/super/*`.

## Batch 1 - Dead Code and Compatibility Cleanup

### Removed files

- `backend/app/domains/podcast/api/routes_subscriptions.py`
- `backend/app/domains/podcast/api/routes_schedule.py`
- `backend/app/scripts/__init__.py`
- `backend/check_users.py`
- `backend/check_tasks.py`
- `backend/delete_preset_models.py`
- `backend/reproduce_error.py`
- `backend/list_routes.py`
- `backend/list_podcast_routes.py`
- `backend/verify_deletion.py`
- `backend/test_alembic_env.py`
- `backend/test_alembic_env_import.py`
- `backend/test_bulk_delete_route.py`
- `backend/test_logic_standalone.py`
- `backend/test_platform_detection.py`
- `backend/test_routes.py`
- Compatibility shims:
  - `backend/app/core/llm_privacy.py`
  - `backend/app/core/file_validation.py`
  - `backend/app/celery_app.py`

### Import path convergence

- `app.core.llm_privacy` -> `app.domains.ai.llm_privacy`
- `app.core.file_validation` -> `app.shared.file_validation`
- `app.celery_app` -> `app.core.celery_app`

### Dependency cleanup

- Removed unused dependencies from `backend/pyproject.toml`:
  - `aioredis`
  - `phonenumbers`
- Consolidated development dependency definition to one location.

## Batch 2 - Task System Rewrite (No `tasks_legacy`)

### Added

- Unified runtime:
  - `backend/app/domains/podcast/tasks/runtime.py`
- Handler modules:
  - `backend/app/domains/podcast/tasks/handlers_transcription.py`
  - `backend/app/domains/podcast/tasks/handlers_summary.py`
  - `backend/app/domains/podcast/tasks/handlers_subscription_sync.py`
  - `backend/app/domains/podcast/tasks/handlers_maintenance.py`
  - `backend/app/domains/podcast/tasks/handlers_recommendation.py`

### Rewritten task entry modules

- `backend/app/domains/podcast/tasks/transcription.py`
- `backend/app/domains/podcast/tasks/summary_generation.py`
- `backend/app/domains/podcast/tasks/subscription_sync.py`
- `backend/app/domains/podcast/tasks/maintenance.py`
- `backend/app/domains/podcast/tasks/recommendation.py`

### Removed

- `backend/app/domains/podcast/tasks_legacy.py`

### Guarantees preserved

- Existing task names remain unchanged.
- Existing queue routing and beat schedule remain centralized in:
  - `backend/app/core/celery_app.py`
- Key runtime behavior retained:
  - transcription lock + dedup dispatch
  - retry on failure for bound tasks
  - background run logging
  - cache cleanup + feed refresh periodic jobs

## Batch 3 - Admin Real Modularization

### Added real admin route modules

- `backend/app/admin/routes/setup_auth.py`
- `backend/app/admin/routes/dashboard.py`
- `backend/app/admin/routes/apikeys.py`
- `backend/app/admin/routes/subscriptions.py`
- `backend/app/admin/routes/users_audit.py`
- `backend/app/admin/routes/monitoring.py`
- `backend/app/admin/routes/settings.py`
- `backend/app/admin/routes/_shared.py`
- `backend/app/admin/routes/_legacy_impl.py` (moved implementation source)

### Changed

- `backend/app/admin/router.py` is now a router aggregator only.
- `backend/app/main.py` imports `app.admin.router` directly.

### Removed old pseudo-modular wrapper layer

- `backend/app/admin/api/common.py`
- `backend/app/admin/api/routes_*.py`
- `backend/app/admin/api/router.py`

## Regression Guardrails

- `backend/tests/test_route_snapshot.py`
- `backend/tests/admin/test_admin_route_snapshot.py`
- `backend/tests/tasks/test_task_registry.py`
- `backend/tests/tasks/test_transcription_task_flow.py`
- `backend/tests/tasks/test_summary_task_flow.py`

## Notes

- Database schema is unchanged.
- This simplification intentionally allows internal import path breaking changes.
