# Phase 2: Backend Architecture Flattening — 5-Layer to 3-Layer

> Continuation of `2026-04-04-codebase-simplification.md`. Phase 1 must be complete before starting.

**Goal:** Remove Repository, Provider/DI, and Projection layers. Merge podcast services from 21 → ~8. Merge podcast tasks from 19 → ~6.

**Risk:** Medium — significant code movement. Rely on existing test suite as safety net.

---

## Part A: Remove Projection Layer (4 files → absorbed into schemas)

### Task 2.1: Read and understand all projection files and their consumers

**Files:**
- Read: `backend/app/domains/podcast/episode_projections.py`
- Read: `backend/app/domains/podcast/playback_queue_projections.py`
- Read: `backend/app/domains/podcast/schedule_projections.py`
- Read: `backend/app/domains/podcast/transcription_schedule_projections.py`
- Read: `backend/app/domains/podcast/schemas.py`
- Read: `backend/app/domains/podcast/api/response_assemblers.py`

- [ ] **Step 1: Read all projection files**

Understand what each projection class does. They are likely DTO/transformer classes that convert ORM models to API response shapes.

- [ ] **Step 2: Read schemas.py and response_assemblers.py**

Understand the current relationship: Model → Projection → Schema → Response.

- [ ] **Step 3: Map the projection fields**

For each projection class, list:
- Source model fields
- Transformed/computed fields
- Where it's consumed (routes, services, tests)

---

### Task 2.2: Merge projections into schemas

**Files:**
- Modify: `backend/app/domains/podcast/schemas.py` — absorb projection logic
- Modify: `backend/app/domains/podcast/api/response_assemblers.py` — use schemas instead of projections
- Modify: All files that import projections (services, routes, tests)
- Delete: `backend/app/domains/podcast/episode_projections.py`
- Delete: `backend/app/domains/podcast/playback_queue_projections.py`
- Delete: `backend/app/domains/podcast/schedule_projections.py`
- Delete: `backend/app/domains/podcast/transcription_schedule_projections.py`

- [ ] **Step 1: Add projection methods to schemas.py**

For each projection class, add a `from_model()` classmethod or a Pydantic model validator to `schemas.py` that performs the same transformation. Example:

```python
# In schemas.py, replace projection:
class PodcastEpisodeResponse(BaseModel):
    # ... existing fields ...
    @classmethod
    def from_orm_model(cls, episode: "PodcastEpisode") -> "PodcastEpisodeResponse":
        return cls(
            # ... field mappings from the old projection ...
        )
```

- [ ] **Step 2: Update response_assemblers.py**

Replace all projection imports and usage with the new schema methods.

- [ ] **Step 3: Update services that import projections**

Files to update:
- `services/episode_service.py` — uses `PodcastEpisodeProjection`
- `services/episode_mapper.py` — uses `PodcastEpisodeProjection`
- `services/playback_service.py` — uses playback queue projections
- `services/queue_service.py` — uses playback queue projections
- `services/search_service.py` — uses `PodcastEpisodeProjection`
- `services/schedule_service.py` — uses `ScheduleConfigProjection`
- `services/transcription_schedule_service.py` — uses transcription projections
- `services/transcription_workflow_service.py` — uses transcription projections

- [ ] **Step 4: Update tests that import projections**

Files to update:
- `tests/test_response_assemblers.py`
- `tests/test_queue_routes.py`
- `tests/test_transcription_schedule_routes.py`
- `backend/app/domains/subscription/tests/test_podcast_schedule_routes.py`

- [ ] **Step 5: Delete projection files**

```bash
rm backend/app/domains/podcast/episode_projections.py
rm backend/app/domains/podcast/playback_queue_projections.py
rm backend/app/domains/podcast/schedule_projections.py
rm backend/app/domains/podcast/transcription_schedule_projections.py
```

- [ ] **Step 6: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "refactor: absorb projection layer into schemas, delete 4 projection files"
```

---

## Part B: Remove Repository Layer (13 files → inline into services)

### Task 2.3: Read and map all repository files

**Files:**
- Read all 13 files in `backend/app/domains/podcast/repositories/`
- Read: `backend/app/core/interfaces/settings_provider.py` and `settings_provider_impl.py`

- [ ] **Step 1: Read each repository file**

For each repo file, document:
- What queries/methods it provides
- Which services use it
- Whether it has complex logic worth preserving vs. trivial query wrappers

- [ ] **Step 2: Create a migration map**

Map each repository method to the service that will absorb it. Most repos are thin wrappers around SQLAlchemy queries.

---

### Task 2.4: Merge repository methods into services (batch 1: episode, feed, content)

**Files:**
- Modify: `backend/app/domains/podcast/services/episode_service.py` — absorb `repositories/episode_query.py` + `repositories/content.py`
- Modify: `backend/app/domains/podcast/services/subscription_service.py` — absorb `repositories/feed.py` + `repositories/subscription_feed.py`

- [ ] **Step 1: Read the target service and source repository files**

- [ ] **Step 2: Move query methods from repositories into services**

Copy the actual SQLAlchemy query logic from the repository into the service. Replace `self.session` with direct `AsyncSession` usage via FastAPI `Depends(get_db_session)`.

- [ ] **Step 3: Update route files to call services instead of repositories**

- [ ] **Step 4: Delete the repository files**

```bash
rm backend/app/domains/podcast/repositories/episode_query.py
rm backend/app/domains/podcast/repositories/content.py
rm backend/app/domains/podcast/repositories/feed.py
rm backend/app/domains/podcast/repositories/subscription_feed.py
```

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: absorb episode/feed/content repositories into services"
```

---

### Task 2.5: Merge repository methods into services (batch 2: playback, queue, transcription, analytics, stats, daily_report)

**Files:**
- Modify: `backend/app/domains/podcast/services/playback_service.py` — absorb `repositories/playback.py` + `repositories/playback_queue.py`
- Modify: `backend/app/domains/podcast/services/queue_service.py` — absorb `repositories/queue.py`
- Modify: `backend/app/domains/podcast/services/daily_report_service.py` — absorb `repositories/daily_report.py`
- Modify: appropriate services — absorb `repositories/analytics.py` + `repositories/stats_search.py` + `repositories/transcription.py`

- [ ] **Step 1: Read remaining repository files**

- [ ] **Step 2: Move query methods into services**

Same pattern as Task 2.4.

- [ ] **Step 3: Delete remaining repository files and `repositories/` directory**

```bash
rm -rf backend/app/domains/podcast/repositories/
```

- [ ] **Step 4: Delete `app/core/interfaces/` directory**

Now that no repositories use `DatabaseSettingsProvider`, delete the interfaces module:
```bash
rm -rf backend/app/core/interfaces/
```
Update any remaining imports in subscription domain if needed.

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: remove podcast repository layer and interfaces module"
```

---

## Part C: Remove Provider/DI Layer

### Task 2.6: Remove `app/core/providers/` and replace with FastAPI native `Depends()`

**Files:**
- Delete: `backend/app/core/providers/__init__.py`
- Delete: `backend/app/core/providers/admin_providers.py`
- Delete: `backend/app/core/providers/ai_providers.py`
- Delete: `backend/app/core/providers/auth_providers.py`
- Delete: `backend/app/core/providers/base_providers.py`
- Delete: `backend/app/core/providers/podcast_providers.py`
- Delete: `backend/app/core/providers/subscription_providers.py`
- Modify: All route files that use providers — replace with `Depends()` directly
- Modify: `backend/app/domains/podcast/api/dependencies.py` — simplify or inline

- [ ] **Step 1: Read each provider file**

Understand what each provider wires up (service instances with DB sessions, config, etc.).

- [ ] **Step 2: Replace provider usage in routes**

In each route file, replace provider-based DI with direct FastAPI `Depends()`:

```python
# Before:
from app.core.providers.podcast_providers import get_episode_service

@router.get("/episodes")
async def list_episodes(service=Depends(get_episode_service)):
    ...

# After:
from app.core.database import get_db_session
from app.domains.podcast.services.episode_service import EpisodeService

async def get_episode_service(session=Depends(get_db_session)):
    return EpisodeService(session)

@router.get("/episodes")
async def list_episodes(service=Depends(get_episode_service)):
    ...
```

Keep simple factory functions in the route modules or a small `dependencies.py` per domain.

- [ ] **Step 3: Delete the providers directory**

```bash
rm -rf backend/app/core/providers/
```

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: remove provider/DI layer, use FastAPI native Depends()"
```

---

## Part D: Merge Podcast Services (21 → ~8)

### Task 2.7: Merge transcription services (4 → 1)

**Files:**
- Merge: `transcription_runtime_service.py` + `transcription_workflow_service.py` + `transcription_schedule_service.py` + `transcription_state_coordinator.py` → `transcription_service.py`
- Delete: the 4 original files

- [ ] **Step 1: Read all 4 transcription service files**

Understand the class structure, public methods, and inter-dependencies.

- [ ] **Step 2: Create `transcription_service.py`**

Combine all 4 into a single `TranscriptionService` class. Organize methods by concern:
- Runtime operations (start, stop, retry)
- Workflow steps (chunk, transcribe, assemble)
- Scheduling (queue management)
- State coordination (status updates)

- [ ] **Step 3: Update all consumers**

Update route files, task handlers, and other services that import from the old files.

- [ ] **Step 4: Delete old files**

```bash
rm backend/app/domains/podcast/services/transcription_runtime_service.py
rm backend/app/domains/podcast/services/transcription_workflow_service.py
rm backend/app/domains/podcast/services/transcription_schedule_service.py
rm backend/app/domains/podcast/services/transcription_state_coordinator.py
```

- [ ] **Step 5: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "refactor: merge 4 transcription services into single transcription_service.py"
```

---

### Task 2.8: Merge summary services (2 → 1)

**Files:**
- Merge: `summary_generation_service.py` + `summary_workflow_service.py` → `summary_service.py`
- Delete: the 2 original files

- [ ] **Step 1: Read both files**

- [ ] **Step 2: Create merged `summary_service.py`**

- [ ] **Step 3: Update consumers, delete old files**

```bash
rm backend/app/domains/podcast/services/summary_generation_service.py
rm backend/app/domains/podcast/services/summary_workflow_service.py
```

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: merge summary services into single summary_service.py"
```

---

### Task 2.9: Merge highlight services (2 → 1)

**Files:**
- Merge: `highlight_extraction_service.py` + `highlight_service.py` → `highlight_service.py`
- Delete: `highlight_extraction_service.py`

- [ ] **Step 1: Read both files**

- [ ] **Step 2: Merge into `highlight_service.py`**

- [ ] **Step 3: Update consumers, delete old file**

```bash
rm backend/app/domains/podcast/services/highlight_extraction_service.py
```

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: merge highlight services into single highlight_service.py"
```

---

### Task 2.10: Clean up remaining service files

**Files:**
- Review and simplify: `episode_service.py`, `playback_service.py`, `subscription_service.py`, `search_service.py`, `daily_report_service.py`
- Review: `services/orchestration/` subdirectory — merge into parent or individual services
- Review these unlisted files for disposition: `daily_report_summary_extractor.py`, `episode_mapper.py`, `schedule_service.py`, `stats_service.py`, `subscription_metadata.py`, `task_orchestration_service.py`

- [ ] **Step 1: Review orchestration/ subdirectory**

5 files: `base.py`, `feed_sync.py`, `maintenance.py`, `report.py`, `transcription.py`.
Determine if these should be absorbed into their parent services or kept as task orchestration helpers.

- [ ] **Step 2: Merge orchestration files into services**

Move methods from orchestration files into the corresponding services.

- [ ] **Step 3: Delete orchestration directory**

```bash
rm -rf backend/app/domains/podcast/services/orchestration/
```

- [ ] **Step 4: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: absorb orchestration subdirectory into services"
```

---

## Part E: Simplify Podcast Tasks (19 → ~6)

### Task 2.11: Merge podcast task files

**Files:**
- Merge: 19 task files into ~6 focused files
- Keep: `__init__.py`, `_runlog.py`, `runtime.py`
- Merge `handlers_*.py` files into their logical parent task files

- [ ] **Step 1: Read all task files**

Understand the handler pattern: `handlers_*.py` files likely contain Celery task definitions that call services.

- [ ] **Step 2: Merge handler files into grouped task files**

Suggested merge:
- `transcription.py` + `handlers_transcription.py` + `handlers_pending_transcription.py` + `pending_transcription.py` → `tasks_transcription.py`
- `summary_generation.py` + `handlers_summary.py` → `tasks_summary.py`
- `subscription_sync.py` + `handlers_subscription_sync.py` → `tasks_subscription.py`
- `daily_report.py` + `handlers_daily_report.py` → `tasks_daily_report.py`
- `highlight_extraction.py` + `handlers_highlight.py` → `tasks_highlight.py`
- `maintenance.py` + `handlers_maintenance.py` + `handlers_opml_import.py` + `opml_import.py` → `tasks_maintenance.py`

- [ ] **Step 3: Update `__init__.py` imports**

Update the task registry to import from new file names.

- [ ] **Step 4: Update `celery_app.py` task routing if needed**

- [ ] **Step 5: Delete old task files**

- [ ] **Step 6: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -m "refactor: merge podcast task files from 19 to ~6"
```

---

### Task 2.12: Simplify `celery_app.py` (4 queues → 2 queues)

**Files:**
- Modify: `backend/app/core/celery_app.py`

- [ ] **Step 1: Read current celery_app.py**

- [ ] **Step 2: Merge queues**

Change task routing:
- `subscription_sync` → `default`
- `ai_generation` → `default`
- `maintenance` → `default`
- `transcription` → keep as `transcription`

Update beat schedule to use only `default` and `transcription` queues.

- [ ] **Step 3: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: simplify celery queues from 4 to 2 (default + transcription)"
```

---

### Task 2.13: Rename `podcast/api/` to `podcast/routes/` and flatten other domains

**Files:**
- Rename: `backend/app/domains/podcast/api/` → `backend/app/domains/podcast/routes/`
- Modify: `backend/app/bootstrap/routers.py` — update import paths

- [ ] **Step 1: Rename the directory**

```bash
mv backend/app/domains/podcast/api backend/app/domains/podcast/routes
```

- [ ] **Step 2: Update all imports**

```bash
cd backend && grep -rn "from app.domains.podcast.api" app/ --include="*.py" | grep -v __pycache__
```
Replace all `from app.domains.podcast.api.` with `from app.domains.podcast.routes.`.

- [ ] **Step 3: Run lint and tests**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: rename podcast/api to podcast/routes"
```

---

## Phase 2 Verification

- [ ] **Final Phase 2 check**

```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q
```

Verify:
- No `repositories/` directory under podcast domain
- No `providers/` directory under core
- No `*_projections.py` files
- ~8 service files under `podcast/services/`
- ~6 task files under `podcast/tasks/`

---

<!-- Phase 3: Docker Simplification — see next file -->
