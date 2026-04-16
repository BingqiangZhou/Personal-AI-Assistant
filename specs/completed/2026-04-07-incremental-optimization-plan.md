# Incremental Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Low-risk, high-impact performance and reliability improvements across backend (indexes, caching, exception narrowing, response models, security fix) and frontend (ListView.builder, design tokens, widget splits).

**Architecture:** Additive changes only — no breaking API changes, no schema changes (indexes are additive). Backend changes are independent from frontend changes and can be executed in parallel.

**Tech Stack:** Python/FastAPI/SQLAlchemy/Alembic/Redis (backend), Flutter/Dart/Riverpod (frontend)

---

## File Map

### Backend — New Files
| File | Responsibility |
|---|---|
| `backend/alembic/versions/023_add_optimization_composite_indexes.py` | Migration adding 4 composite indexes |

### Backend — Modified Files
| File | Change |
|---|---|
| `backend/app/core/redis/cache.py` | Add 3 cache methods to `PodcastCacheOperations` |
| `backend/app/domains/podcast/schemas.py` | Add 3 response models (`SubscriptionDeleteResponse`, `SubscriptionRefreshResponse`, `SubscriptionReparseResponse`) |
| `backend/app/domains/podcast/routes/routes_subscriptions.py` | Apply response models to 3 endpoints |
| `backend/app/domains/media/transcription/service.py:557-558` | Remove API key partial logging |
| `backend/app/domains/podcast/services/summary_service.py:338` | Narrow `except Exception` |
| `backend/app/domains/podcast/services/task_orchestration_service.py:618` | Narrow `except Exception` |
| `backend/app/domains/podcast/services/transcription_workflow_service.py:347` | Narrow `except Exception` |
| `backend/app/domains/podcast/transcription_state.py:354` | Narrow `except Exception` |
| `backend/app/domains/ai/services/model_runtime_service.py:279` | Narrow `except Exception` |

### Frontend — Modified Files
| File | Change |
|---|---|
| `frontend/lib/features/podcast/presentation/pages/podcast_feed_page.dart:~246` | `ListView(children:)` → `ListView.builder` |
| `frontend/lib/features/podcast/presentation/widgets/podcast_queue_sheet.dart:~339` | `ListView(children:)` → `ListView.builder` (in `_QueueLoadingState` and `_QueueStateList`) |
| `frontend/lib/features/podcast/presentation/pages/podcast_downloads_page.dart:~245` | `ListView(children:)` → `ListView.builder` |
| `frontend/lib/features/profile/presentation/pages/profile_cache_management_page.dart:~662` | Keep `ListView(children:)` (fixed small list) |
| 15-20 widget files | Replace `BorderRadius.circular(N)` with `AppRadius` tokens |
| `frontend/lib/features/podcast/presentation/widgets/podcast_queue_sheet.dart` | Split into sub-widgets |
| `frontend/lib/features/podcast/presentation/widgets/transcription_status_widget.dart` | Split into sub-widgets |

---

## Task 1: Database Composite Indexes

**Files:**
- Create: `backend/alembic/versions/023_add_optimization_composite_indexes.py`

- [ ] **Step 1: Write the Alembic migration**

Create `backend/alembic/versions/023_add_optimization_composite_indexes.py`:

```python
"""Add composite indexes for common multi-column query patterns

Revision ID: 023
Revises: 022
Create Date: 2026-04-07

Adds composite indexes for:
- podcast_episodes: (subscription_id, published_at) — fetch recent episodes per subscription
- podcast_playback_states: (user_id, last_updated_at) — playback history by time
- subscriptions: (source_type, status) — feed refresh filtering
- transcription_tasks: (episode_id, status) — failed/cancelled task lookup
"""

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None

from alembic import op


def upgrade() -> None:
    op.create_index(
        "idx_episodes_subscription_published",
        "podcast_episodes",
        ["subscription_id", "published_at"],
    )
    op.create_index(
        "idx_playback_states_user_updated",
        "podcast_playback_states",
        ["user_id", "last_updated_at"],
    )
    op.create_index(
        "idx_subscriptions_source_status",
        "subscriptions",
        ["source_type", "status"],
    )
    op.create_index(
        "idx_transcription_episode_status",
        "transcription_tasks",
        ["episode_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("idx_transcription_episode_status", table_name="transcription_tasks")
    op.drop_index("idx_subscriptions_source_status", table_name="subscriptions")
    op.drop_index("idx_playback_states_user_updated", table_name="podcast_playback_states")
    op.drop_index("idx_episodes_subscription_published", table_name="podcast_episodes")
```

- [ ] **Step 2: Run migration to verify it applies**

Run: `cd backend && uv run alembic upgrade head`
Expected: No errors, migration 023 applied.

- [ ] **Step 3: Run migration downgrade+upgrade to verify reversibility**

Run: `cd backend && uv run alembic downgrade -1 && uv run alembic upgrade head`
Expected: No errors.

- [ ] **Step 4: Run existing tests**

Run: `cd backend && uv run pytest -x -q`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add backend/alembic/versions/023_add_optimization_composite_indexes.py
git commit -m "perf: add 4 composite indexes for common query patterns

- podcast_episodes(subscription_id, published_at)
- podcast_playback_states(user_id, last_updated_at)
- subscriptions(source_type, status)
- transcription_tasks(episode_id, status)"
```

---

## Task 2: Security Fix — Remove API Key Partial Logging

**Files:**
- Modify: `backend/app/domains/media/transcription/service.py:555-561`

- [ ] **Step 1: Replace the insecure log line**

In `backend/app/domains/media/transcription/service.py`, find the block around line 555-561:

```python
# BEFORE:
try:
    api_key = decrypt_data(model_config.api_key)
    logger.info(
        f"[KEY] Decrypted API key for model {model_config.name} (first 10 chars): {api_key[:10]}...",
    )
except Exception as e:
    logger.error(f"Failed to decrypt API key: {e}")
```

Replace with:

```python
# AFTER:
try:
    api_key = decrypt_data(model_config.api_key)
    logger.debug("API key decrypted for model %s", model_config.name)
except Exception as e:
    logger.error("Failed to decrypt API key for model %s: %s", model_config.name, e)
```

- [ ] **Step 2: Verify no other key material is logged**

Run: `cd backend && grep -rn "api_key\[:.\+\]" app/ || echo "No partial key logging found"`
Expected: "No partial key logging found"

- [ ] **Step 3: Run existing tests**

Run: `cd backend && uv run pytest -x -q`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add backend/app/domains/media/transcription/service.py
git commit -m "fix(security): remove partial API key from info-level log"
```

---

## Task 3: Exception Narrowing — summary_service.py

**Files:**
- Modify: `backend/app/domains/podcast/services/summary_service.py:338`

- [ ] **Step 1: Read the current code and imports**

Read `backend/app/domains/podcast/services/summary_service.py` lines 1-15 and lines 330-345.

The current pattern at line 338:
```python
except Exception:
    await self.db.rollback()
    raise
```

This is a DB commit/rollback block. The correct exception type is `SQLAlchemyError` (or its subclasses like `IntegrityError`, `OperationalError`).

- [ ] **Step 2: Add SQLAlchemyError import and narrow the except**

Check if `SQLAlchemyError` is already imported. If not, add it. Then change:

```python
# BEFORE:
except Exception:
    await self.db.rollback()
    raise

# AFTER:
except Exception:
    await self.db.rollback()
    raise
```

Note: After investigation, this pattern (`except Exception: rollback; raise`) is actually the **correct** DB transaction pattern — it catches any error during commit, rolls back, then re-raises. Narrowing here would risk missing real DB errors. **Skip this file** — the pattern is correct as-is for DB transaction safety.

- [ ] **Step 3: Commit if changes were made, otherwise skip to next task**

No changes needed for this file — the rollback-and-reraise pattern is the correct DB safety net.

---

## Task 4: Exception Narrowing — 5 Remaining Service Files

**Files:**
- Modify: `backend/app/domains/podcast/services/task_orchestration_service.py:618`
- Modify: `backend/app/domains/podcast/services/transcription_workflow_service.py:347`
- Modify: `backend/app/domains/podcast/transcription_state.py:354`
- Modify: `backend/app/domains/ai/services/model_runtime_service.py:279`
- Modify: `backend/app/domains/podcast/services/highlight_service.py` (AI call blocks)

- [ ] **Step 1: Read each file's except block and identify the correct narrowing**

For each file, read the context around the `except Exception` line to determine what exceptions can actually be raised. Key patterns:

- **External HTTP/AI calls**: `httpx.HTTPStatusError`, `httpx.TimeoutException`, `json.JSONDecodeError`
- **Redis operations**: `redis.exceptions.RedisError`
- **File I/O**: `OSError`, `IOError`
- **DB operations**: Keep `except Exception` with rollback+reraise (see Task 3 rationale)

- [ ] **Step 2: Apply narrowings for each file**

For each file, check the imports already present and add any needed. Then narrow the except clause:

**`task_orchestration_service.py:618`** — wraps an external service call:
```python
# Check context and narrow to:
except (httpx.HTTPStatusError, httpx.TimeoutException, asyncio.TimeoutError):
```

**`transcription_workflow_service.py:347`** — wraps per-episode processing:
```python
# Check context and narrow to:
except (OSError, httpx.HTTPStatusError, ValueError):
```

**`transcription_state.py:354`** — wraps Redis state lookup:
```python
# Check context and narrow to:
except (redis.exceptions.RedisError, ValueError):
```

**`model_runtime_service.py:279`** — wraps AI API call:
```python
# Check context and narrow to:
except (httpx.HTTPStatusError, httpx.TimeoutException, json.JSONDecodeError):
```

**`highlight_service.py`** AI calls — wraps JSON parsing and external calls:
```python
# Check context and narrow to:
except (json.JSONDecodeError, httpx.HTTPStatusError, httpx.TimeoutException):
```

- [ ] **Step 3: Run existing tests**

Run: `cd backend && uv run pytest -x -q`
Expected: All tests pass.

- [ ] **Step 4: Commit**

```bash
git add backend/app/domains/podcast/services/task_orchestration_service.py \
        backend/app/domains/podcast/services/transcription_workflow_service.py \
        backend/app/domains/podcast/transcription_state.py \
        backend/app/domains/ai/services/model_runtime_service.py \
        backend/app/domains/podcast/services/highlight_service.py
git commit -m "fix: narrow bare except Exception to specific types in service layer

Remaining rollback-and-reraise patterns intentionally left as except Exception
since they are the correct DB transaction safety net."
```

---

## Task 5: Response Model Completion

**Files:**
- Modify: `backend/app/domains/podcast/schemas.py`
- Modify: `backend/app/domains/podcast/routes/routes_subscriptions.py`

- [ ] **Step 1: Add response models to schemas.py**

At the end of the Subscription section in `backend/app/domains/podcast/schemas.py` (before the Episode section around line 120), add:

```python
class SubscriptionDeleteResponse(BaseSchema):
    """Response for DELETE /subscriptions/{id}."""
    success: bool = True
    message: str = "Subscription deleted"
    subscription_id: int


class SubscriptionRefreshResponse(BaseSchema):
    """Response for POST /subscriptions/{id}/refresh."""
    success: bool = True
    new_episodes: int = 0
    message: str = ""


class SubscriptionReparseResponse(BaseSchema):
    """Response for POST /subscriptions/{id}/reparse."""
    success: bool = True
    result: dict[str, Any] = {}
```

- [ ] **Step 2: Apply response models to routes**

In `backend/app/domains/podcast/routes/routes_subscriptions.py`:

**Delete endpoint (~line 172-173):**
```python
# BEFORE:
# TODO: Add a proper response model (e.g. ActionSuccessResponse) instead of raw dict
return {"success": True, "message": "Subscription deleted"}

# AFTER:
return SubscriptionDeleteResponse(subscription_id=subscription_id)
```

**Refresh endpoint (~line 186-191):**
```python
# BEFORE:
# TODO: Add a proper response model (e.g. RefreshResponse) instead of raw dict
return {
    "success": True,
    "new_episodes": len(new_episodes),
    "message": f"Updated, found {len(new_episodes)} new episodes",
}

# AFTER:
return SubscriptionRefreshResponse(
    new_episodes=len(new_episodes),
    message=f"Updated, found {len(new_episodes)} new episodes",
)
```

**Reparse endpoint (~line 213-214):**
```python
# BEFORE:
# TODO: Add a proper response model (e.g. ReparseResponse) instead of raw dict
return {"success": True, "result": result}

# AFTER:
return SubscriptionReparseResponse(result=result)
```

Also add `response_model=SubscriptionDeleteResponse` (etc.) to the route decorators if other routes in the file use `response_model`.

- [ ] **Step 3: Add imports to routes file**

Add to the imports at the top of `routes_subscriptions.py`:
```python
from app.domains.podcast.schemas import (
    # ... existing imports ...
    SubscriptionDeleteResponse,
    SubscriptionRefreshResponse,
    SubscriptionReparseResponse,
)
```

- [ ] **Step 4: Run existing tests**

Run: `cd backend && uv run pytest -x -q`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add backend/app/domains/podcast/schemas.py \
        backend/app/domains/podcast/routes/routes_subscriptions.py
git commit -m "feat: add typed response models for subscription delete/refresh/reparse endpoints"
```

---

## Task 6: Redis Caching — Episode Detail Cache

**Files:**
- Modify: `backend/app/core/redis/cache.py` (add cache method to `PodcastCacheOperations`)
- Modify: whichever service/repo method fetches episode detail with summary

- [ ] **Step 1: Read the existing `PodcastCacheOperations` class**

Read `backend/app/core/redis/cache.py` lines 242-534 to understand existing cache method patterns. Note the TTL constants, key format, and `cache_get_with_lock` usage.

- [ ] **Step 2: Add episode detail cache method**

Add to `PodcastCacheOperations` in `cache.py`:

```python
# Episode detail caching
_EPISODE_DETAIL_TTL = 300  # 5 minutes
_EPISODE_DETAIL_PREFIX = "episode:detail"

async def get_episode_detail(
    self, episode_id: int, loader: Callable[[], Awaitable[dict | None]]
) -> dict | None:
    """Cache episode detail (with summary) with 5-minute TTL."""
    key = f"{self._EPISODE_DETAIL_PREFIX}:{episode_id}"
    return await self.cache_get_with_lock(key, loader, ttl=self._EPISODE_DETAIL_TTL)

async def invalidate_episode_detail(self, episode_id: int) -> None:
    """Invalidate episode detail cache after update or summary generation."""
    await safe_cache_invalidate(f"{self._EPISODE_DETAIL_PREFIX}:{episode_id}")
```

- [ ] **Step 3: Wire cache into the episode detail fetch path**

Find the service method that fetches episode detail with summary (likely in `episode_service.py` or a repository mixin). Wrap the DB query with `cache.get_episode_detail()`, and add `cache.invalidate_episode_detail()` in methods that update episodes or generate summaries.

- [ ] **Step 4: Write a test for the cache method**

Add to existing Redis cache tests:

```python
async def test_episode_detail_cache_hit():
    """Cached episode detail is returned without calling loader."""
    cache = PodcastCacheOperations(...)
    await cache._set_json("episode:detail:42", {"id": 42, "title": "Cached"})

    called = False
    async def loader():
        nonlocal called
        called = True
        return {"id": 42, "title": "Fresh"}

    result = await cache.get_episode_detail(42, loader)
    assert result["title"] == "Cached"
    assert not called
```

- [ ] **Step 5: Run tests**

Run: `cd backend && uv run pytest -x -q`
Expected: All tests pass.

- [ ] **Step 6: Commit**

```bash
git add backend/app/core/redis/cache.py \
        backend/app/domains/podcast/services/episode_service.py
git commit -m "perf: add Redis cache for episode detail with 5-minute TTL"
```

---

## Task 7: Redis Caching — Highlight Dates + Playback Rate

**Files:**
- Modify: `backend/app/core/redis/cache.py`
- Modify: `backend/app/domains/podcast/services/highlight_service.py`
- Modify: relevant playback rate service/repo

- [ ] **Step 1: Add highlight dates cache method**

Add to `PodcastCacheOperations` in `cache.py`:

```python
_HIGHLIGHT_DATES_TTL = 600  # 10 minutes
_HIGHLIGHT_DATES_PREFIX = "highlights:dates"

async def get_highlight_dates(
    self, user_id: int, loader: Callable[[], Awaitable[list[str]]]
) -> list[str]:
    key = f"{self._HIGHLIGHT_DATES_PREFIX}:{user_id}"
    result = await self.cache_get_with_lock(key, loader, ttl=self._HIGHLIGHT_DATES_TTL)
    return result or []

async def invalidate_highlight_dates(self, user_id: int) -> None:
    await safe_cache_invalidate(f"{self._HIGHLIGHT_DATES_PREFIX}:{user_id}")
```

- [ ] **Step 2: Add playback rate cache method**

Add to `PodcastCacheOperations` in `cache.py`:

```python
_PLAYBACK_RATE_TTL = 1800  # 30 minutes
_PLAYBACK_RATE_PREFIX = "playback:rate"

async def get_effective_playback_rate(
    self, user_id: int, episode_id: int, loader: Callable[[], Awaitable[float]]
) -> float:
    key = f"{self._PLAYBACK_RATE_PREFIX}:{user_id}:{episode_id}"
    result = await self.cache_get_with_lock(key, loader, ttl=self._PLAYBACK_RATE_TTL)
    return result if isinstance(result, (int, float)) else await loader()

async def invalidate_playback_rate(self, user_id: int, episode_id: int) -> None:
    await safe_cache_invalidate(f"{self._PLAYBACK_RATE_PREFIX}:{user_id}:{episode_id}")
```

- [ ] **Step 3: Wire caches into service methods**

For highlight dates: find `get_highlight_dates` in `highlight_service.py` (~line 846) and wrap with cache. Add `invalidate_highlight_dates` in methods that extract highlights or toggle favorites.

For playback rate: find `get_effective_playback_rate` and wrap with cache. Add `invalidate_playback_rate` where rate is changed.

- [ ] **Step 4: Run tests**

Run: `cd backend && uv run pytest -x -q`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add backend/app/core/redis/cache.py \
        backend/app/domains/podcast/services/highlight_service.py
git commit -m "perf: add Redis caches for highlight dates (10m TTL) and playback rate (30m TTL)"
```

---

## Task 8: Frontend — ListView.builder Migration

**Files:**
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_feed_page.dart:~246`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_downloads_page.dart:~245`
- Modify: `frontend/lib/features/podcast/presentation/widgets/podcast_queue_sheet.dart:~339,~373`

- [ ] **Step 1: Migrate podcast_feed_page.dart**

Find the `ListView(children:)` around line 246. The pattern will look like:

```dart
// BEFORE:
child: ListView(
  padding: const EdgeInsets.symmetric(vertical: 4),
  children: [
    // ... list of widget items
  ],
),
```

Change to:

```dart
// AFTER:
child: ListView.builder(
  padding: const EdgeInsets.symmetric(vertical: 4),
  cacheExtent: ScrollConstants.largeListCacheExtent,
  itemCount: items.length,
  itemBuilder: (context, index) {
    final item = items[index];
    return /* widget for item */;
  },
),
```

Note: Read the full context to understand how `children` is populated. If the list is generated from a `map()` call, extract the source list. If it's a mix of static + dynamic items, use `SliverList` or add static items as header/footer.

- [ ] **Step 2: Migrate podcast_downloads_page.dart**

Find the `ListView` around line 245. The pattern:

```dart
// BEFORE:
child: ListView(
  padding: const EdgeInsets.only(left: 8, right: 8, top: 8, bottom: 100),
  children: allTasks.map(
    (task) => Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: _DownloadTaskCard(task: task),
    ),
  ).toList(),
),
```

Change to:

```dart
// AFTER:
child: ListView.builder(
  padding: const EdgeInsets.only(left: 8, right: 8, top: 8, bottom: 100),
  itemCount: allTasks.length,
  itemBuilder: (context, index) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: _DownloadTaskCard(task: allTasks[index]),
    );
  },
),
```

- [ ] **Step 3: Migrate podcast_queue_sheet.dart**

In `_QueueLoadingState` (~line 339) and `_QueueStateList` (~line 373), these use `ListView` with a fixed small number of children (loading/empty state). These are fine as-is since they have 1-3 items. **Skip these** — they don't benefit from builder.

- [ ] **Step 4: Run Flutter analyze and tests**

Run: `cd frontend && flutter analyze`
Expected: No new errors.

Run: `cd frontend && flutter test`
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add frontend/lib/features/podcast/presentation/pages/podcast_feed_page.dart \
        frontend/lib/features/podcast/presentation/pages/podcast_downloads_page.dart
git commit -m "perf: migrate large ListView(children:) to ListView.builder for lazy rendering"
```

---

## Task 9: Frontend — Design Token Migration (BorderRadius)

**Files:**
- Modify: `frontend/lib/core/constants/app_radius.dart` (if missing tokens)
- Modify: 15-20 widget files

- [ ] **Step 1: Audit all hardcoded BorderRadius values**

Run: `cd frontend && grep -rn "BorderRadius\.circular(" lib/ | grep -v "AppRadius" | grep -v ".g.dart"`

Map each found value to an existing `AppRadius` token:
- `circular(6)` → `AppRadius.xsRadius`
- `circular(8)` → `AppRadius.smRadius` or `AppRadius.item`
- `circular(10)` → `AppRadius.mdRadius` or `AppRadius.button`
- `circular(12)` → no existing token — add `AppRadius.mdLg` or use closest
- `circular(14)` → `AppRadius.lgRadius` or `AppRadius.card`
- `circular(16)` → no existing token — add or use closest
- `circular(18)` → no existing token — add
- `circular(20)` → `AppRadius.xlRadius`

- [ ] **Step 2: Add missing radius tokens to AppRadius if needed**

In `frontend/lib/core/constants/app_radius.dart`, add any missing values identified in the audit:

```dart
// Add after line 36 (xl = 20):
static const double mdLg = 12;
static const double lgXl = 16;
static const double lgXx = 18;
```

And corresponding pre-built instances:

```dart
static BorderRadius get mdLgRadius => BorderRadius.circular(mdLg);
static BorderRadius get lgXlRadius => BorderRadius.circular(lgXl);
static BorderRadius get lgXxRadius => BorderRadius.circular(lgXx);
```

- [ ] **Step 3: Replace hardcoded values across all widget files**

For each file identified in the audit, replace `BorderRadius.circular(N)` with the corresponding `AppRadius` getter. Example:

```dart
// BEFORE:
borderRadius: BorderRadius.circular(12),

// AFTER:
borderRadius: AppRadius.mdLgRadius,
```

Work file by file. After replacing each file, run `flutter analyze` to verify.

- [ ] **Step 4: Run Flutter analyze**

Run: `cd frontend && flutter analyze`
Expected: No new errors.

- [ ] **Step 5: Commit**

```bash
git add frontend/lib/core/constants/app_radius.dart \
        frontend/lib/features/ \
        frontend/lib/shared/ \
        frontend/lib/core/widgets/
git commit -m "style: replace hardcoded BorderRadius.circular with AppRadius tokens"
```

---

## Task 10: Frontend — Split podcast_queue_sheet.dart

**Files:**
- Modify: `frontend/lib/features/podcast/presentation/widgets/podcast_queue_sheet.dart`
- Create: `frontend/lib/features/podcast/presentation/widgets/queue/queue_list_widget.dart`
- Create: `frontend/lib/features/podcast/presentation/widgets/queue/queue_controls_widget.dart`
- Create: `frontend/lib/features/podcast/presentation/widgets/queue/queue_empty_state_widget.dart`

- [ ] **Step 1: Read the full file to understand widget boundaries**

Read `frontend/lib/features/podcast/presentation/widgets/podcast_queue_sheet.dart` (1024 lines). Map each private widget class to its line range and dependencies.

- [ ] **Step 2: Extract `_QueueList` and `_QueueListItem` into queue_list_widget.dart**

Create `frontend/lib/features/podcast/presentation/widgets/queue/queue_list_widget.dart` containing:
- `_QueueList` (line ~429)
- `_QueueListState` (line ~438)
- `_QueueListItem` (line ~629)
- `_StaticQueueSubtitle` (line ~760)
- `_CurrentQueueSubtitle` (line ~783)
- `_QueueItemCover` (line ~865)
- `_EqualizerBadge` (line ~941)
- `_QueueItemDownloadIndicator` (line ~977)

Make internal classes public (remove underscore prefix) since they're now in separate files: `QueueList`, `QueueListItem`, etc.

- [ ] **Step 3: Extract `_QueueLoadingState` and loading/empty states**

Create `frontend/lib/features/podcast/presentation/widgets/queue/queue_empty_state_widget.dart` containing:
- `_QueueLoadingState` (line ~331) → `QueueLoadingState`
- `_QueueStateList` (line ~357) → `QueueEmptyStateList`

- [ ] **Step 4: Extract header and info chips**

Create `frontend/lib/features/podcast/presentation/widgets/queue/queue_controls_widget.dart` containing:
- `_QueueHeader` (line ~190) → `QueueHeader`
- `_QueueInfoChip` (line ~285) → `QueueInfoChip`

- [ ] **Step 5: Update main sheet to import extracted widgets**

In `podcast_queue_sheet.dart`, replace the extracted classes with imports:

```dart
import 'queue/queue_list_widget.dart';
import 'queue/queue_controls_widget.dart';
import 'queue/queue_empty_state_widget.dart';
```

The main file should now be ~200-250 lines containing only `PodcastQueueSheet`, `_QueuePanel`, and the import statements.

- [ ] **Step 6: Run Flutter analyze**

Run: `cd frontend && flutter analyze`
Expected: No errors.

- [ ] **Step 7: Run tests**

Run: `cd frontend && flutter test`
Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
git add frontend/lib/features/podcast/presentation/widgets/podcast_queue_sheet.dart \
        frontend/lib/features/podcast/presentation/widgets/queue/
git commit -m "refactor: split podcast_queue_sheet.dart into focused sub-widgets"
```

---

## Task 11: Frontend — Split transcription_status_widget.dart

**Files:**
- Modify: `frontend/lib/features/podcast/presentation/widgets/transcription_status_widget.dart`
- Create: `frontend/lib/features/podcast/presentation/widgets/transcription/transcript_tab_widget.dart`
- Create: `frontend/lib/features/podcast/presentation/widgets/transcription/transcription_progress_widget.dart`

- [ ] **Step 1: Read the full file to understand method boundaries**

Read `frontend/lib/features/podcast/presentation/widgets/transcription_status_widget.dart` (972 lines). Map each build method:

| Method | Lines | Category |
|---|---|---|
| `build()` | 26-45 | Main router |
| `_buildNotStartedState()` | 47-147 | Main widget |
| `_startTranscriptionWithFeedback()` | 149-181 | Main widget |
| `_buildPendingState()` | 183-263 | Progress |
| `_buildProcessingState()` | 265-533 | Progress |
| `_buildCompletedState()` | 535-696 | Main widget |
| `_buildFailedState()` | 698-856 | Main widget |
| `_getFriendlyErrorMessage()` | 858-885 | Helper |
| `_getErrorSuggestion()` | 887-909 | Helper |
| `_buildStatItem()` | 911-938 | Helper |
| Helper methods | 940-972 | Helper |

- [ ] **Step 2: Extract progress/pending/processing into transcription_progress_widget.dart**

Create `frontend/lib/features/podcast/presentation/widgets/transcription/transcription_progress_widget.dart` containing builder functions:

```dart
/// Builds the pending state indicator.
Widget buildPendingState(BuildContext context, {...}) { ... }

/// Builds the processing state with progress ring and steps.
Widget buildProcessingState(BuildContext context, {...}) { ... }
```

These are pure builder functions (or a private widget class) that receive the needed state as parameters.

- [ ] **Step 3: Extract completed/failed states into transcript_tab_widget.dart**

Create `frontend/lib/features/podcast/presentation/widgets/transcription/transcript_tab_widget.dart` containing:

```dart
/// Builds the completed transcription state.
Widget buildCompletedState(BuildContext context, {...}) { ... }

/// Builds the failed transcription state.
Widget buildFailedState(BuildContext context, {...}) { ... }
```

Along with the helper methods `_getFriendlyErrorMessage`, `_getErrorSuggestion`, `_buildStatItem`, `_formatDuration`, `_formatAccuracy`.

- [ ] **Step 4: Update main widget to import extracted builders**

In `transcription_status_widget.dart`, import the new files and call the extracted functions from the main `build()` method's switch.

The main file should be ~200-250 lines.

- [ ] **Step 5: Run Flutter analyze**

Run: `cd frontend && flutter analyze`
Expected: No errors.

- [ ] **Step 6: Run tests**

Run: `cd frontend && flutter test`
Expected: All tests pass.

- [ ] **Step 7: Commit**

```bash
git add frontend/lib/features/podcast/presentation/widgets/transcription_status_widget.dart \
        frontend/lib/features/podcast/presentation/widgets/transcription/
git commit -m "refactor: split transcription_status_widget.dart into focused sub-widgets"
```

---

## Dependency Order

```
Task 1 (DB Indexes)          ← independent, do first (backend)
Task 2 (Security Fix)        ← independent (backend)
Task 3 (Exception - summary)  ← SKIP after analysis
Task 4 (Exception - others)  ← independent (backend)
Task 5 (Response Models)     ← independent (backend)
Task 6 (Cache - Episode)     ← depends on Task 1 (needs indexes for perf baseline)
Task 7 (Cache - Others)      ← depends on Task 6 (same file, cache.py)
Task 8 (ListView.builder)    ← independent (frontend)
Task 9 (Design Tokens)       ← independent (frontend)
Task 10 (Queue Sheet Split)  ← independent (frontend)
Task 11 (Transcription Split) ← independent (frontend)
```

**Parallelizable groups:**
- Backend: Tasks 1, 2, 4, 5 can run in parallel → then Tasks 6, 7 sequentially
- Frontend: Tasks 8, 9, 10, 11 can all run in parallel
- Backend + Frontend can run in parallel with each other
