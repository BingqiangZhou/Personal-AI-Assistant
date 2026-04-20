# Backend Simplification: Phase 5 & Phase 6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simplify Celery to single-queue mode, merge worker+beat, simplify bootstrap, remove obsolete models, create Alembic migration, verify everything works.

**Architecture:** Single Celery queue (default), worker+beat in one process, no task run logging, no distributed locks.

**Tech Stack:** Python 3.11+, Celery, Redis, Docker Compose, Alembic

---

## Phase 5: Celery & Tasks Simplification

### Task 5.1: Simplify runtime.py — Remove log_task_run, single_instance_task_lock, _runlog

**Files:**
- Modify: `backend/app/domains/podcast/tasks/runtime.py`
- Delete: `backend/app/domains/podcast/tasks/_runlog.py`

- [ ] **Step 1: Rewrite runtime.py**

Replace entire file with simplified version keeping only `ensure_orm_models_registered`, `worker_session`, `run_async`. Remove `log_task_run`, `single_instance_task_lock`, and the `_runlog` import.

- [ ] **Step 2: Delete _runlog.py**

```bash
rm backend/app/domains/podcast/tasks/_runlog.py
```

- [ ] **Step 3: Verify**

```bash
cd backend && uv run python -c "from app.domains.podcast.tasks.runtime import ensure_orm_models_registered, worker_session, run_async; print('OK')"
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/domains/podcast/tasks/runtime.py && git rm backend/app/domains/podcast/tasks/_runlog.py && git commit -m "refactor(tasks): remove log_task_run, single_instance_task_lock, and _runlog from runtime"
```

---

### Task 5.2: Simplify celery_app.py — Single queue, 4 beat tasks

**Files:**
- Modify: `backend/app/core/celery_app.py`

- [ ] **Step 1: Rewrite celery_app.py**

Key changes:
1. Remove all `task_routes` config
2. Beat schedule reduced to 4 entries (remove log-task-statistics, extract-pending-highlights, process-pending-transcriptions)
3. Remove `dispose_runlog_engine` from shutdown hook
4. Keep `_LazyCeleryApp` proxy

Beat schedule target:
```python
{
    "refresh-podcast-feeds": crontab(minute=0),
    "generate-pending-summaries": 1800.0,
    "generate-daily-podcast-reports": crontab(hour=19, minute=30),
    "auto-cleanup-cache": crontab(hour=4, minute=0),
}
```

- [ ] **Step 2: Verify**

```bash
cd backend && uv run python -c "from app.core.celery_app import celery_app; print(type(celery_app))"
```

- [ ] **Step 3: Commit**

```bash
git add backend/app/core/celery_app.py && git commit -m "refactor(celery): remove task routing, transcription queue, simplify beat schedule to 4 tasks"
```

---

### Task 5.3: Simplify all 6 task files

**Files:**
- Modify: `backend/app/domains/podcast/tasks/tasks_maintenance.py`
- Modify: `backend/app/domains/podcast/tasks/tasks_summary.py`
- Modify: `backend/app/domains/podcast/tasks/tasks_subscription.py`
- Modify: `backend/app/domains/podcast/tasks/tasks_highlight.py`
- Modify: `backend/app/domains/podcast/tasks/tasks_transcription.py`
- Modify: `backend/app/domains/podcast/tasks/tasks_daily_report.py`
- Modify: `backend/app/domains/podcast/tasks/__init__.py`

- [ ] **Step 1: For each task file, remove:**
- All `log_task_run(...)` calls
- All `single_instance_task_lock(...)` context managers
- `from app.domains.podcast.tasks.runtime import log_task_run, single_instance_task_lock` imports
- The `log_periodic_task_statistics` task from `tasks_maintenance.py`

- [ ] **Step 2: Update __init__.py** — Remove `log_periodic_task_statistics` from exports

- [ ] **Step 3: Run task tests**

```bash
cd backend && uv run pytest tests/tasks/ -x -v
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/domains/podcast/tasks/ && git commit -m "refactor(tasks): remove log_task_run, single_instance_task_lock from all task files"
```

---

### Task 5.4: Update Celery test files

**Files:**
- Modify: `backend/tests/tasks/test_task_registry.py`
- Modify: `backend/tests/tasks/test_celery_task_routes.py`
- Modify: `backend/tests/test_celery_config_snapshot.py`
- Modify: `backend/tests/tasks/test_summary_task_flow.py`
- Modify: `backend/tests/tasks/test_pending_transcription_task_flow.py`

- [ ] **Step 1: Update each test file:**
- Remove task routing assertions (no more `task_routes`)
- Remove `single_instance_task_lock` mocks
- Remove `log_task_run` mocks
- Update beat schedule snapshot to expect 4 entries
- Update task registry to expect 13 tasks (without `log_periodic_task_statistics`)

- [ ] **Step 2: Run tests**

```bash
cd backend && uv run pytest tests/tasks/ tests/test_celery_config_snapshot.py -x -v
```

- [ ] **Step 3: Commit**

```bash
git add backend/tests/tasks/ backend/tests/test_celery_config_snapshot.py && git commit -m "test(tasks): update Celery tests for simplified single-user mode"
```

---

### Task 5.5: Merge celery_worker + celery_beat in Docker Compose

**Files:**
- Modify: `docker/docker-compose.yml`

- [ ] **Step 1: Edit docker-compose.yml**

Merge `celery_worker` and `celery_beat` into a single `celery_worker` service:
- Change command to: `celery -A app.core.celery_app:celery_app worker -B --loglevel=${CELERY_LOG_LEVEL:-info} --concurrency=1 -Q default`
- Remove the `celery_beat` service block entirely
- Remove `OBS_ALERT_*` environment variables from `backend` service
- Update header comment from 6 services to 5

- [ ] **Step 2: Run full test suite**

```bash
cd backend && uv run pytest -x -q
```

- [ ] **Step 3: Commit**

```bash
git add docker/docker-compose.yml && git commit -m "refactor(docker): merge celery_worker + celery_beat, remove OBS_ALERT vars"
```

---

## Phase 6: Bootstrap, Tests, Docker & Final Cleanup

### Task 6.1: Simplify bootstrap/lifecycle.py — Remove cache warming

**Files:**
- Modify: `backend/app/bootstrap/lifecycle.py`

- [ ] **Step 1: Remove cache warming from lifecycle**

Remove:
- The `_run_cache_warmup_async` function
- The `execute_cache_warmup` import
- The `asyncio.create_task(_run_cache_warmup_async(...))` call in startup

Keep: DB/Redis init, health checks, stale transcription reset, shutdown sequence.

- [ ] **Step 2: Commit**

```bash
git add backend/app/bootstrap/lifecycle.py && git commit -m "refactor(bootstrap): remove cache warming from lifecycle"
```

---

### Task 6.2: Simplify bootstrap/http.py — Remove first_run_middleware

**Files:**
- Modify: `backend/app/bootstrap/http.py`

- [ ] **Step 1: Remove first_run_middleware**

Remove these lines from `configure_middlewares`:
```python
from app.admin.first_run import first_run_middleware
app.middleware("http")(first_run_middleware)
```

- [ ] **Step 2: Commit**

```bash
git add backend/app/bootstrap/http.py && git commit -m "refactor(bootstrap): remove first_run_middleware from HTTP bootstrap"
```

---

### Task 6.3: Simplify bootstrap/routers.py — Remove user and subscription routers

**Files:**
- Modify: `backend/app/bootstrap/routers.py`

- [ ] **Step 1: Remove obsolete router imports**

Remove `user_router` and `subscription_router` imports and their `include_router` calls. Keep only `podcast_router`, `podcast_subscription_router`, and `admin_router`.

- [ ] **Step 2: Commit**

```bash
git add backend/app/bootstrap/routers.py && git commit -m "refactor(bootstrap): remove user and subscription routers"
```

---

### Task 6.4: Simplify core/security/encryption.py — Remove AES-256-GCM

**Files:**
- Modify: `backend/app/core/security/encryption.py`
- Modify: `backend/app/core/security/__init__.py`
- Modify: `backend/app/admin/services/apikeys_service.py`

- [ ] **Step 1: Remove AES-256-GCM functions from encryption.py**

Remove: `encrypt_data_with_password`, `decrypt_data_with_password`, `validate_export_password`
Keep: `encrypt_data`, `decrypt_data` (Fernet only)

- [ ] **Step 2: Update __init__.py re-exports**

Remove `encrypt_data_with_password`, `decrypt_data_with_password`, `validate_export_password` from re-exports.

- [ ] **Step 3: Update apikeys_service.py**

Remove encrypted export/import mode. Keep plaintext-only export/import.
Update imports to remove `encrypt_data_with_password`, `decrypt_data_with_password`, `validate_export_password`.

- [ ] **Step 4: Update tests/core/test_security.py**

Remove `TestValidateExportPassword` class.

- [ ] **Step 5: Run tests**

```bash
cd backend && uv run pytest tests/core/test_security.py -x -v
```

- [ ] **Step 6: Commit**

```bash
git add backend/app/core/security/ backend/app/admin/services/apikeys_service.py backend/tests/core/test_security.py && git commit -m "refactor(security): remove AES-256-GCM export/import, keep Fernet only"
```

---

### Task 6.5: Remove BackgroundTaskRun model

**Files:**
- Modify: `backend/app/admin/models.py`

- [ ] **Step 1: Remove BackgroundTaskRun class from admin/models.py**

Keep `SystemSettings`, remove the `BackgroundTaskRun` class and its `__table_args__`.

- [ ] **Step 2: Commit**

```bash
git add backend/app/admin/models.py && git commit -m "refactor(admin): remove BackgroundTaskRun model"
```

---

### Task 6.6: Create Alembic migration — Drop obsolete tables

**Files:**
- Create: `backend/alembic/versions/025_drop_simplification_tables.py`

- [ ] **Step 1: Generate migration**

```bash
cd backend && uv run alembic revision -m "drop_simplification_tables"
```

- [ ] **Step 2: Edit migration — add drop_table operations**

```python
def upgrade() -> None:
    op.drop_table("background_task_runs")
    op.drop_table("password_resets")
    op.drop_table("user_sessions")
    op.drop_table("subscription_category_mappings")
    op.drop_table("subscription_categories")
    op.drop_table("subscription_items")

def downgrade() -> None:
    raise NotImplementedError("Cannot downgrade beyond simplification migration")
```

- [ ] **Step 3: Verify migration**

```bash
cd backend && uv run alembic upgrade head --sql 2>&1 | head -30
```

- [ ] **Step 4: Commit**

```bash
git add backend/alembic/versions/025_*.py && git commit -m "migration: drop obsolete tables (background_task_runs, user_sessions, password_resets, subscription_*)"
```

---

### Task 6.7: Verify dependency cleanup

**Files:**
- Modify: `backend/pyproject.toml` (verify/clean only)

- [ ] **Step 1: Check no remaining imports of removed packages**

```bash
cd backend && grep -rn "import jwt\b\|from jwt\|import bcrypt\|from bcrypt\|import itsdangerous\|from itsdangerous\|import email_validator\|from email_validator" app/ --include="*.py" | grep -v __pycache__
```

If zero results, verify `pyjwt`, `bcrypt`, `itsdangerous`, `email-validator` are absent from `pyproject.toml`. Remove if present.

- [ ] **Step 2: Re-sync dependencies**

```bash
cd backend && uv sync --extra dev
```

- [ ] **Step 3: Commit (only if changes)**

```bash
git add backend/pyproject.toml backend/uv.lock && git commit -m "chore: remove unused dependencies (pyjwt, bcrypt, itsdangerous, email-validator)"
```

---

### Task 6.8: Final validation — Full test suite + lint + Docker smoke test

**Files:** None (verification only)

- [ ] **Step 1: Run ruff lint**

```bash
cd backend && uv run ruff check . --fix
```

Fix any issues and commit if needed.

- [ ] **Step 2: Run full backend test suite**

```bash
cd backend && uv run pytest -x -q
```

All tests must pass.

- [ ] **Step 3: Verify app imports**

```bash
cd backend && uv run python -c "from app.main import app; print('App imports OK')"
```

- [ ] **Step 4: Docker smoke test**

```bash
cd docker && docker compose up -d && sleep 15 && curl -f http://localhost:8000/api/v1/health
```

Expected: `{"status":"healthy"}`

- [ ] **Step 5: Verify 5 Docker services**

```bash
cd docker && docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

Expected: `postgres`, `redis`, `backend`, `celery_worker`, `nginx` (5 total).

- [ ] **Step 6: Tear down**

```bash
cd docker && docker compose down
```

---

## Frontend Auth Changes (Deferred)

The following frontend files need updating in a separate plan:

| File | Change |
|------|--------|
| `frontend/lib/features/auth/data/datasources/auth_remote_datasource.dart` | Remove register, refresh, forgot-password, reset-password endpoints; use X-API-Key header |
| `frontend/lib/features/auth/presentation/providers/auth_provider.dart` | Remove register, token refresh flows |
| `frontend/lib/core/network/dio_client.dart` | Change Authorization header to X-API-Key |
| `frontend/lib/core/network/token_refresh_service.dart` | Delete |
| `frontend/lib/features/auth/presentation/pages/register_page.dart` | Delete |
| `frontend/lib/features/auth/presentation/pages/forgot_password_page.dart` | Delete |
| `frontend/lib/features/auth/presentation/pages/reset_password_page.dart` | Delete |
