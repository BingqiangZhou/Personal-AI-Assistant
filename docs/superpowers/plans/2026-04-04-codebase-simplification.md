# Codebase Simplification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simplify the Stella codebase from enterprise-over-engineered to right-sized — all features retained, ~45% code reduction.

**Architecture:** Flatten backend from 5-layer DDD to 3-layer (Route → Service → Model). Delete unused infrastructure. Merge Docker services. Clean up frontend dead code and consolidate providers.

**Tech Stack:** FastAPI + SQLAlchemy 2.x async (backend), Flutter + Riverpod 3.x (frontend), Docker Compose (deployment)

**Design Doc:** `docs/designs/2026-04-04-codebase-simplification-design.md`

**Execution order:** Phases must run sequentially. Within each phase, tasks can often run in parallel where noted.

**Plan files:**
- Phase 1 (this file): Backend Infrastructure Deletion — 11 tasks
- [Phase 2](2026-04-04-codebase-simplification-phase2.md): Backend Architecture Flattening — 13 tasks (incl. api→routes rename)
- [Phase 3](2026-04-04-codebase-simplification-phase3.md): Docker Simplification — 3 tasks (7→6 containers)
- [Phase 4](2026-04-04-codebase-simplification-phase4.md): Frontend Dead Code + Model Consolidation — 4 tasks
- [Phase 5-6](2026-04-04-codebase-simplification-phase5-6.md): Frontend Playback Refactor + Provider Reduction — 10 tasks

**Total: ~41 tasks across 6 phases**

**Note:** The design doc says "7→5 containers" but actual count is 7→6 (2 celery workers merge into 1, gunicorn removal doesn't reduce container count). The `subscription/`, `user/`, and `ai/` domains keep their current structure per the "keep, simplify" principle — full flattening is scoped to the podcast domain only.

---

## Phase 1: Backend Infrastructure Deletion

**Goal:** Remove monitoring, circuit breaker, rate limiter, email stub, interfaces, and ETag modules. Simplify middleware and Redis. Delete performance tests. Remove unused dependencies.

**Risk:** Low — these modules have minimal coupling to business logic.

### Task 1.1: Delete `app/core/circuit_breaker.py` and remove all references

**Files:**
- Delete: `backend/app/core/circuit_breaker.py`
- Delete: `backend/tests/core/test_circuit_breaker.py`
- Modify: `backend/app/core/exceptions.py` — remove `CircuitOpenError` import and class
- Modify: `backend/app/domains/ai/services/model_runtime_service.py` — remove circuit breaker usage

- [ ] **Step 1: Read the files that reference circuit_breaker to understand current usage**

Read these files:
- `backend/app/core/circuit_breaker.py` — full file
- `backend/app/core/exceptions.py` — find `CircuitOpenError` import and where it's used
- `backend/app/domains/ai/services/model_runtime_service.py` — find circuit breaker import and usage
- `backend/tests/core/test_circuit_breaker.py` — full file
- `backend/tests/core/test_exception_handlers.py` — find `CircuitOpenError` reference

- [ ] **Step 2: Remove circuit_breaker import from `app/core/exceptions.py`**

Remove the line:
```python
from app.core.circuit_breaker import CircuitOpenError
```
And remove the `CircuitOpenError` exception class definition (or its re-export) from exceptions.py.

- [ ] **Step 3: Remove circuit_breaker usage from `app/domains/ai/services/model_runtime_service.py`**

Remove:
```python
from app.core.circuit_breaker import CircuitOpenError, get_circuit_breaker
```
Remove any `@circuit_breaker` decorator or `CircuitOpenError` catch blocks. Replace with direct call (no wrapper).

- [ ] **Step 4: Remove `CircuitOpenError` from `tests/core/test_exception_handlers.py`**

Remove any test cases or imports referencing `CircuitOpenError`.

- [ ] **Step 5: Delete the circuit_breaker module and its test**

```bash
rm backend/app/core/circuit_breaker.py
rm backend/tests/core/test_circuit_breaker.py
```

- [ ] **Step 6: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```
Expected: All tests pass, no lint errors.

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "refactor: remove circuit_breaker module and all references"
```

---

### Task 1.2: Delete `app/core/metrics.py` and `app/core/observability.py` and remove references

**Files:**
- Delete: `backend/app/core/metrics.py`
- Delete: `backend/app/core/observability.py`
- Delete: `backend/tests/core/test_metrics_endpoint.py`
- Delete: `backend/tests/core/test_observability.py`
- Modify: `backend/app/bootstrap/http.py` — remove metrics/observability imports and middleware setup
- Modify: `backend/app/admin/routes/monitoring.py` — remove metrics/observability imports and endpoints (note: admin is frozen per design, but these endpoints call deleted modules — stub them)

- [ ] **Step 1: Read referencing files**

Read:
- `backend/app/bootstrap/http.py` — find metrics/observability imports and usage
- `backend/app/admin/routes/monitoring.py` — find metrics/observability imports and usage

- [ ] **Step 2: Remove metrics/observability from `bootstrap/http.py`**

Remove imports:
```python
from app.core.metrics import get_prometheus_metrics
from app.core.observability import build_observability_snapshot
```
Remove any middleware or route registration that uses these. Remove the `/metrics` endpoint mount or prometheus route.

- [ ] **Step 3: Stub or simplify `admin/routes/monitoring.py`**

Since admin is frozen, replace the metrics/observability endpoint bodies with minimal stubs that return empty/simple responses, removing the imports:
```python
# Remove:
from app.core.observability import build_observability_snapshot
from app.core.redis import get_null_redis_runtime_metrics, get_shared_redis
```

- [ ] **Step 4: Delete the modules and their tests**

```bash
rm backend/app/core/metrics.py
rm backend/app/core/observability.py
rm backend/tests/core/test_metrics_endpoint.py
rm backend/tests/core/test_observability.py
```

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: remove prometheus metrics and observability modules"
```

---

### Task 1.3: Delete `app/core/middleware/rate_limit.py` and remove references

**Files:**
- Delete: `backend/app/core/middleware/rate_limit.py`
- Delete: `backend/app/core/redis/rate_limit.py`
- Delete: `backend/tests/core/test_rate_limit_improvements.py`
- Delete: `backend/tests/core/test_rate_limit_middleware.py`
- Modify: `backend/app/bootstrap/http.py` — remove rate limit import and middleware setup

- [ ] **Step 1: Read referencing files**

Read:
- `backend/app/bootstrap/http.py` — find `RateLimitConfig` and `setup_rate_limiting` usage
- `backend/app/core/redis/rate_limit.py` — verify only used by rate limiter middleware

- [ ] **Step 2: Remove rate limit setup from `bootstrap/http.py`**

Remove:
```python
from app.core.middleware.rate_limit import RateLimitConfig, setup_rate_limiting
```
Remove any call to `setup_rate_limiting()` or `RateLimitConfig`.

- [ ] **Step 3: Delete the rate limit files and tests**

```bash
rm backend/app/core/middleware/rate_limit.py
rm backend/app/core/redis/rate_limit.py
rm backend/tests/core/test_rate_limit_improvements.py
rm backend/tests/core/test_rate_limit_middleware.py
```

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: remove distributed rate limiting middleware"
```

---

### Task 1.4: Delete `app/core/middleware/response_optimization.py` and simplify middleware `__init__.py`

**Files:**
- Delete: `backend/app/core/middleware/response_optimization.py`
- Modify: `backend/app/bootstrap/http.py` — remove response_optimization import
- Modify: `backend/app/core/middleware/__init__.py` — remove `get_performance_middleware` deprecation stub, simplify to keep only `RequestLoggingMiddleware`

- [ ] **Step 1: Read referencing files**

Read:
- `backend/app/bootstrap/http.py` — find response_optimization import
- `backend/app/core/middleware/__init__.py` — full file

- [ ] **Step 2: Remove response_optimization from `bootstrap/http.py`**

Remove:
```python
from app.core.middleware.response_optimization import ...
```
Remove any middleware add call for response optimization.

- [ ] **Step 3: Simplify `middleware/__init__.py`**

Remove `get_performance_middleware()` stub and `RequestObservabilityMiddleware` alias. Keep only `RequestLoggingMiddleware` class. Target: ~60-80 lines (from 162).

- [ ] **Step 4: Delete the file**

```bash
rm backend/app/core/middleware/response_optimization.py
```

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: remove response optimization middleware, simplify request logging"
```

---

### Task 1.5: Delete `app/core/email.py` and `app/core/interfaces/`

**Files:**
- Delete: `backend/app/core/email.py`
- Delete: `backend/app/core/interfaces/settings_provider.py`
- Delete: `backend/app/core/interfaces/settings_provider_impl.py`
- Delete: `backend/app/core/interfaces/__init__.py`
- Modify: `backend/app/domains/user/services/auth_service.py` — remove email_service import and usage

- [ ] **Step 1: Read referencing files**

Read:
- `backend/app/core/email.py` — understand the email_service interface
- `backend/app/domains/user/services/auth_service.py` — find email_service usage

- [ ] **Step 2: Remove email usage from auth_service.py**

Remove:
```python
from app.core.email import email_service
```
Remove any calls to `email_service` methods (send password reset, etc.). These were stubs — remove the call sites entirely.

- [ ] **Step 3: Delete email module**

```bash
rm backend/app/core/email.py
```

- [ ] **Step 4: Delete interfaces directory**

The `interfaces/` module is only used by repository files (`podcast/repositories/base.py`, `subscription/repositories/subscription_repository.py`, `subscription/services/subscription_service.py`). Since podcast repositories are removed in Phase 2 Task 2.5, defer interfaces deletion to that task. For now, skip this step.

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: remove email stub and interfaces module"
```

---

### Task 1.6: Delete ETag module and simplify response helpers

**Files:**
- Delete: `backend/app/core/etag.py`
- Modify: `backend/app/http/responses.py` — remove ETag import, simplify
- Modify: `backend/app/domains/podcast/api/routes_episodes.py` — remove `build_etag_response` import and usage
- Modify: `backend/app/domains/podcast/api/routes_stats.py` — remove `build_conditional_etag_response` import and usage
- Modify: `backend/app/domains/podcast/api/routes_subscriptions.py` — remove `build_conditional_etag_response` import and usage
- Delete: `backend/tests/core/test_etag.py`

- [ ] **Step 1: Read referencing files**

Read all files listed above to understand ETag usage patterns.

- [ ] **Step 2: Remove ETag from route files**

In each route file (`routes_episodes.py`, `routes_stats.py`, `routes_subscriptions.py`):
- Remove the ETag import
- Replace `build_etag_response(...)` / `build_conditional_etag_response(...)` calls with direct `return result` or `JSONResponse(content=result)`

- [ ] **Step 3: Simplify or delete `http/responses.py`**

If `responses.py` only contained ETag helpers, delete it. Otherwise, keep the non-ETag parts.

- [ ] **Step 4: Delete the files**

```bash
rm backend/app/core/etag.py
rm backend/tests/core/test_etag.py
```

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: remove ETag module and simplify response helpers"
```

---

### Task 1.7: Simplify Redis module (6 files → 2 files)

**Files:**
- Keep: `backend/app/core/redis/client.py`, `backend/app/core/redis/cache.py`
- Delete: `backend/app/core/redis/metrics_collector.py`, `backend/app/core/redis/sorted_set.py`, `backend/app/core/redis/podcast_cache.py`, `backend/app/core/redis/lock.py`
- Modify: `backend/app/core/redis/__init__.py` — update exports

- [ ] **Step 1: Read all redis files to understand dependencies**

Read every file in `backend/app/core/redis/`. Check which are used by business logic vs. only by deleted modules (metrics, rate limit, observability).

- [ ] **Step 2: Determine which redis files to keep**

Likely:
- `client.py` — core Redis connection, **keep**
- `cache.py` — cache operations, **keep** (may need to absorb podcast_cache functionality)
- `lock.py` — distributed locking, check usage. Used in lifecycle.py for startup lock. **Keep if used.**
- `metrics_collector.py` — only used by deleted metrics module, **delete**
- `sorted_set.py` — check usage, likely only metrics/rate_limit, **delete**
- `podcast_cache.py` — check usage, may need to merge into `cache.py`
- `rate_limit.py` — already deleted in Task 1.3

- [ ] **Step 3: Merge `podcast_cache.py` into `cache.py` if needed**

If `podcast_cache.py` has podcast-specific cache methods used by services, move those methods into `cache.py`.

- [ ] **Step 4: Update `__init__.py` exports**

Remove exports for deleted modules. Keep only what's needed.

- [ ] **Step 5: Delete the redundant files**

```bash
rm backend/app/core/redis/metrics_collector.py
rm backend/app/core/redis/sorted_set.py
# Keep or delete podcast_cache.py based on Step 3
```

- [ ] **Step 6: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "refactor: simplify redis module, remove metrics_collector and sorted_set"
```

---

### Task 1.8: Delete performance tests

**Files:**
- Delete: `backend/tests/performance/` directory

- [ ] **Step 1: Delete the directory**

```bash
rm -rf backend/tests/performance/
```

- [ ] **Step 2: Remove `locust` dev dependency from pyproject.toml**

- [ ] **Step 3: Run lint and tests**

```bash
cd backend && uv sync --extra dev && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: remove performance test suite and locust dependency"
```

---

### Task 1.9: Remove unused Python dependencies

**Files:**
- Modify: `backend/pyproject.toml` — remove unused deps

- [ ] **Step 1: Verify each dependency has zero imports**

```bash
cd backend
grep -r "gunicorn" app/ --include="*.py" | grep -v __pycache__ | grep import
grep -r "email_validator" app/ --include="*.py" | grep -v __pycache__ | grep import
grep -r "prometheus_client" app/ --include="*.py" | grep -v __pycache__ | grep import
grep -r "from starlette" app/ --include="*.py" | grep -v __pycache__ | grep import
```

- [ ] **Step 2: Remove from `pyproject.toml`**

Remove these lines from dependencies:
- `gunicorn>=25.1.0`
- `email-validator>=2.3.0`
- `prometheus-client>=0.21.0`
- `starlette>=1.0.0` (transitive via FastAPI)

- [ ] **Step 3: Sync and verify**

```bash
cd backend && uv sync --extra dev && uv run pytest --timeout=60 -q
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "chore: remove unused backend dependencies (gunicorn, email-validator, prometheus, starlette)"
```

---

### Task 1.10: Simplify `app/core/exceptions.py`

**Files:**
- Modify: `backend/app/core/exceptions.py`

- [ ] **Step 1: Read the full exceptions.py file**

- [ ] **Step 2: Identify which exceptions are actually raised**

```bash
cd backend
# Find all exception classes defined in exceptions.py
grep "^class.*Error\|^class.*Exception\|^class.*Fault" app/core/exceptions.py
# For each, check if it's actually raised anywhere
for exc in $(grep "^class" app/core/exceptions.py | awk '{print $2}' | sed 's/(.*//'); do
  count=$(grep -r "$exc" app/ --include="*.py" | grep -v __pycache__ | grep "raise $exc" | wc -l)
  echo "$exc: raised $count times"
done
```

- [ ] **Step 3: Remove unreferenced exceptions**

Keep only exceptions that are actually raised or caught. Remove the rest. Target: ~150 lines (from ~545).

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: simplify exceptions.py, remove unused exception classes"
```

---

### Task 1.11: Simplify `app/core/database.py`

**Files:**
- Modify: `backend/app/core/database.py`

- [ ] **Step 1: Read database.py, identify pool warmup and monitoring code**

- [ ] **Step 2: Remove `warmup_connection_pool()` and monitoring functions**

Remove: `warmup_connection_pool()`, `get_db_pool_snapshot()`, pool metrics logging from `init_db()`.

- [ ] **Step 3: Simplify `init_db()`**

Remove the pool warmup call. Keep model registration and basic initialization.

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: simplify database.py, remove pool warmup and monitoring"
```

---

## Phase 1 Verification

- [ ] **Final Phase 1 check**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```
All tests must pass before proceeding to Phase 2.

---

<!-- Phase 2 will be written in a separate file for manageability -->
<!-- See: 2026-04-04-codebase-simplification-phase2.md -->
