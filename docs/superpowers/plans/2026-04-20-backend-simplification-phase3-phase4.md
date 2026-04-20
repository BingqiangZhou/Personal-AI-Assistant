# Backend Simplification: Phase 3 & Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Consolidate 4 domains into 2, merge 13 repositories into 2, merge 14 services into 6, merge 6 AI services into 2.

**Architecture:** Merge subscription/media/content domains into podcast. Flatten repository mixin pattern into 2 flat repository classes. Merge tightly-coupled services into single files. Remove multi-user task orchestration.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy async, Redis, Celery

---

## Phase 3: Domain Consolidation

### Task 3.1: Move subscription models into podcast/models.py

**Files:**
- Modify: `backend/app/domains/podcast/models.py`
- Modify: `backend/app/domains/subscription/models.py` (extract, then delete)

- [ ] **Step 1: Add subscription models to podcast/models.py**

Append these models to the end of `backend/app/domains/podcast/models.py` (before any re-exports if they still exist):

```python
# --- Subscription models (merged from domains/subscription) ---

class SubscriptionType(str, enum.Enum):
    PODCAST = "podcast"
    NEWSLETTER = "newsletter"
    WEBSITE = "website"


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class UpdateFrequency(str, enum.Enum):
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Copy all columns from subscription/models.py Subscription class
    # Include: source_url, source_type, title, description, image_url,
    #          site_url, feed_url, author, language, etag, last_modified,
    #          last_fetched_at, last_error, fetch_count, is_active,
    #          created_at, updated_at
    # Copy relationships and indexes exactly


class UserSubscription(Base):
    __tablename__ = "user_subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Copy all columns from subscription/models.py UserSubscription class
    # Include: user_id, subscription_id, update_frequency, custom_title,
    #          is_active, last_read_at, created_at, updated_at
    # Copy relationships and indexes exactly
```

Action: Open `backend/app/domains/subscription/models.py`, copy the 5 models (`SubscriptionType`, `SubscriptionStatus`, `UpdateFrequency`, `Subscription`, `UserSubscription`) with all their columns, relationships, indexes, and properties. Paste into `podcast/models.py`. Do NOT copy `SubscriptionItem`, `SubscriptionCategory`, `SubscriptionCategoryMapping` — these are being removed.

- [ ] **Step 2: Update all imports from subscription.models**

Run these search-and-replace operations across the codebase:

```bash
cd backend && grep -rn "from app.domains.subscription.models import" app/ --include="*.py" | grep -v __pycache__
```

For each file found, change the import path:
- `from app.domains.subscription.models import X` → `from app.domains.podcast.models import X`

Specific files to update:
- `app/domains/podcast/repositories/base.py` (line ~35, lazy import)
- `app/domains/podcast/repositories/content.py` (line ~40, lazy import)
- `app/domains/podcast/repositories/playback_queue.py` (line ~45, lazy import)
- `app/domains/podcast/services/daily_report_service.py` (line ~19)
- `app/domains/podcast/services/highlight_service.py` (line ~30)
- `app/domains/podcast/services/schedule_service.py` (line ~11)
- `app/domains/podcast/services/subscription_service.py` (line ~24-25)
- `app/domains/podcast/services/task_orchestration_service.py` (line ~47)

- [ ] **Step 3: Verify imports resolve**

```bash
cd backend && uv run python -c "from app.domains.podcast.models import Subscription, UserSubscription, SubscriptionType, SubscriptionStatus, UpdateFrequency; print('OK')"
```

- [ ] **Step 4: Commit**

```bash
git add backend/app/domains/podcast/models.py backend/app/domains/podcast/repositories/ backend/app/domains/podcast/services/ && git commit -m "refactor(podcast): move subscription models into podcast/models.py"
```

---

### Task 3.2: Move subscription parsers into podcast/parsers/

**Files:**
- Create: `backend/app/domains/podcast/parsers/__init__.py`
- Create: `backend/app/domains/podcast/parsers/feed_parser.py`
- Create: `backend/app/domains/podcast/parsers/feed_schemas.py`
- Modify: `backend/app/domains/podcast/services/summary_service.py` (update import)

- [ ] **Step 1: Create podcast/parsers/ directory and copy files**

```bash
mkdir -p backend/app/domains/podcast/parsers
cp backend/app/domains/subscription/parsers/__init__.py backend/app/domains/podcast/parsers/
cp backend/app/domains/subscription/parsers/feed_parser.py backend/app/domains/podcast/parsers/
cp backend/app/domains/subscription/parsers/feed_schemas.py backend/app/domains/podcast/parsers/
```

- [ ] **Step 2: Update podcast/parsers/__init__.py imports**

Change any internal imports from `app.domains.subscription.parsers` to `app.domains.podcast.parsers`.

- [ ] **Step 3: Update import in summary_service.py**

In `backend/app/domains/podcast/services/summary_service.py` line ~27:
```python
# Before:
from app.domains.subscription.parsers.feed_parser import strip_html_tags
# After:
from app.domains.podcast.parsers.feed_parser import strip_html_tags
```

- [ ] **Step 4: Verify**

```bash
cd backend && uv run python -c "from app.domains.podcast.parsers.feed_parser import strip_html_tags; print('OK')"
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/domains/podcast/parsers/ backend/app/domains/podcast/services/summary_service.py && git commit -m "refactor(podcast): move subscription parsers into podcast/parsers/"
```

---

### Task 3.3: Move subscription repository into podcast

**Files:**
- Modify: `backend/app/domains/podcast/services/subscription_service.py` (update import)
- Modify: `backend/app/domains/podcast/routes/dependencies.py` (update import)

- [ ] **Step 1: Copy SubscriptionRepository code**

Copy the `SubscriptionRepository` class from `backend/app/domains/subscription/repositories/subscription_repository.py` into `backend/app/domains/podcast/repositories/subscription_feed.py` (or a new file `backend/app/domains/podcast/repositories/subscription_repository.py`).

Update the class's internal imports from `app.domains.subscription.models` to `app.domains.podcast.models`.

- [ ] **Step 2: Update subscription_service.py import**

In `backend/app/domains/podcast/services/subscription_service.py` line ~25:
```python
# Before:
from app.domains.subscription.repositories import SubscriptionRepository
# After:
from app.domains.podcast.repositories.subscription_repository import SubscriptionRepository
```

- [ ] **Step 3: Update routes/dependencies.py**

In `backend/app/domains/podcast/routes/dependencies.py` line ~31:
```python
# Before:
from app.domains.subscription.api.dependencies import get_subscription_repository
# After: inline the dependency or import from new location
```

Replace with a local function that creates the repository:
```python
def get_subscription_repository(db=Depends(get_db_session_dependency)):
    from app.domains.podcast.repositories.subscription_repository import SubscriptionRepository
    return SubscriptionRepository(db)
```

- [ ] **Step 4: Verify**

```bash
cd backend && uv run python -c "from app.domains.podcast.repositories.subscription_repository import SubscriptionRepository; print('OK')"
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/domains/podcast/ && git commit -m "refactor(podcast): move subscription repository into podcast domain"
```

---

### Task 3.4: Move media models and transcription into podcast

**Files:**
- Modify: `backend/app/domains/podcast/models.py` (add media models, remove re-exports)
- Move: `backend/app/domains/media/transcription/` → `backend/app/domains/podcast/transcription/`
- Modify: `backend/app/domains/podcast/services/transcription_runtime_service.py` (update import)

- [ ] **Step 1: Add media models to podcast/models.py**

Copy from `backend/app/domains/media/models/transcript.py` and `backend/app/domains/media/models/transcription_task.py`:
- `PodcastEpisodeTranscript` (40 lines)
- `TranscriptionStatus` enum
- `TranscriptionStep` enum
- `TranscriptionTask` (182 lines)

Paste into `podcast/models.py`. Then remove the re-export lines (~310-315):
```python
# Remove these lines:
from app.domains.media.models.transcript import PodcastEpisodeTranscript
from app.domains.media.models.transcription_task import (TranscriptionStatus, TranscriptionStep, TranscriptionTask)
```

- [ ] **Step 2: Move transcription/ directory**

```bash
cp -r backend/app/domains/media/transcription/ backend/app/domains/podcast/transcription/
```

Update any internal imports within the moved files that reference `app.domains.media`.

- [ ] **Step 3: Update transcription_runtime_service.py**

In `backend/app/domains/podcast/services/transcription_runtime_service.py` line ~17:
```python
# Before:
from app.domains.media.transcription import PodcastTranscriptionService, SiliconFlowTranscriber
# After:
from app.domains.podcast.transcription import PodcastTranscriptionService, SiliconFlowTranscriber
```

- [ ] **Step 4: Verify**

```bash
cd backend && uv run python -c "from app.domains.podcast.models import PodcastEpisodeTranscript, TranscriptionTask; from app.domains.podcast.transcription import PodcastTranscriptionService; print('OK')"
```

- [ ] **Step 5: Commit**

```bash
git add backend/app/domains/podcast/ && git commit -m "refactor(podcast): move media models and transcription into podcast domain"
```

---

### Task 3.5: Move content models into podcast and delete content/media/subscription domains

**Files:**
- Modify: `backend/app/domains/podcast/models.py` (add content models, remove re-exports)
- Delete: `backend/app/domains/content/` (entire directory)
- Delete: `backend/app/domains/media/` (entire directory, after transcription moved)
- Delete: `backend/app/domains/subscription/` (entire directory, after models/parsers/repos moved)
- Modify: `backend/app/core/database.py` (update model registration)

- [ ] **Step 1: Add content models to podcast/models.py**

Copy from `backend/app/domains/content/models/`:
- `ConversationSession`, `PodcastConversation` from `conversation.py` (136 lines)
- `PodcastDailyReport`, `PodcastDailyReportItem` from `daily_report.py` (112 lines)
- `EpisodeHighlight`, `HighlightExtractionTask` from `highlight.py` (156 lines)

Paste into `podcast/models.py`. Then remove the re-export lines (~298-309):
```python
# Remove these lines:
from app.domains.content.models.conversation import ConversationSession, PodcastConversation
from app.domains.content.models.daily_report import PodcastDailyReport, PodcastDailyReportItem
from app.domains.content.models.highlight import EpisodeHighlight, HighlightExtractionTask
```

- [ ] **Step 2: Update database model registration**

In `backend/app/core/database.py` function `register_orm_models()`, remove these lines:
```python
    "app.domains.subscription.models",
    "app.domains.user.models",
```

Note: `app.domains.media.models` and `app.domains.content.models` may not be registered here (check). If they are, remove those too.

- [ ] **Step 3: Delete obsolete domain directories**

```bash
rm -rf backend/app/domains/content/
rm -rf backend/app/domains/media/
rm -rf backend/app/domains/subscription/
```

- [ ] **Step 4: Verify no remaining imports from deleted domains**

```bash
cd backend && grep -rn "from app.domains.content\|from app.domains.media\|from app.domains.subscription\|from app.domains.user" app/ --include="*.py" | grep -v __pycache__
```

Expected: zero results. If any remain, update them to point to `app.domains.podcast.models` or the new locations.

- [ ] **Step 5: Run tests**

```bash
cd backend && uv run pytest -x -q --ignore=tests/integration
```

- [ ] **Step 6: Commit**

```bash
git add -A backend/app/domains/ backend/app/core/database.py && git commit -m "refactor: merge subscription/media/content domains into podcast, delete obsolete domains"
```

---

### Task 3.6: Clean up shared/schemas.py

**Files:**
- Modify: `backend/app/shared/schemas.py`

- [ ] **Step 1: Remove user/token/subscription/conversation/password schemas**

Remove these Pydantic model classes from `backend/app/shared/schemas.py`:
- `UserCreate`, `UserUpdate`, `UserResponse`
- `Token`, `RefreshTokenRequest`
- `ForgotPasswordRequest`, `ResetPasswordRequest`, `PasswordResetResponse`
- Any subscription-specific schemas (if present, e.g. `SubscriptionCreate`, `SubscriptionUpdate`)

Keep: `BaseSchema`, `TimestampedSchema`, `PaginatedResponse`, `PaginationParams`, `APIResponse`, `ErrorResponse`

- [ ] **Step 2: Update `shared/__init__.py`**

Remove re-exports of deleted schemas from `backend/app/shared/__init__.py`.

- [ ] **Step 3: Verify no remaining imports of deleted schemas**

```bash
cd backend && grep -rn "UserCreate\|UserUpdate\|UserResponse\|ForgotPasswordRequest\|ResetPasswordRequest\|PasswordResetResponse" app/ --include="*.py" | grep -v __pycache__
```

Expected: zero results.

- [ ] **Step 4: Commit**

```bash
git add backend/app/shared/ && git commit -m "refactor(shared): remove user/token/subscription schemas from shared"
```

---

## Phase 4: Repository & Service Layer Simplification

### Task 4.1: Merge 13 podcast repositories into 2 files

**Files:**
- Create: `backend/app/domains/podcast/repositories/podcast_repository.py`
- Create: `backend/app/domains/podcast/repositories/content_repository.py`
- Delete: all existing repository files in `backend/app/domains/podcast/repositories/`
- Modify: `backend/app/domains/podcast/routes/dependencies.py`

- [ ] **Step 1: Create podcast_repository.py**

Consolidate into one class `PodcastRepository` the methods from:
- `base.py` — `_active_user_subscription_filters`, `_podcast_source_type_filter`, `_cache_episode_metadata`, `get_playback_state`, `get_playback_states_batch`
- `content.py` — `create_or_update_subscription`, `create_or_update_episode`, `create_or_update_episodes_batch`, `get_unsummarized_episodes`, `get_pending_summaries_for_user`, `get_episode_by_id`, `update_ai_summary`, `mark_summary_failed`
- `feed.py` — `get_user_subscriptions_paginated`, `get_episodes_paginated`, `get_feed_lightweight_page_paginated`, `get_feed_lightweight_cursor_paginated`, `get_feed_cursor_paginated`, `get_playback_history_paginated`, etc.
- `analytics.py` — `search_episodes`, `update_subscription_fetch_time`, `get_recently_played`, `get_liked_episodes`, `get_profile_stats_aggregated`, `get_user_stats_aggregated`
- `playback_queue.py` — `update_playback_progress`, `get_or_create_queue`, `get_queue_with_items`, `add_or_move_to_tail`, `remove_item`, `activate_episode`, `reorder_items`, `set_current`, `complete_current`, `get_effective_playback_rate`

Strategy: Create a single class with all methods. All lazy imports from subscription.models are now direct imports from podcast.models. Remove the `_get_subscription_models()` lazy-loading pattern.

```python
"""Podcast repository — consolidated from 13 mixin-based files."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.models import (
    PodcastEpisode, PodcastPlaybackState, PodcastQueue, PodcastQueueItem,
    Subscription, UserSubscription, SubscriptionStatus,
    # ... other needed models
)


class PodcastRepository:
    """Single repository for all podcast queries."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # Paste methods from all mixins here, updating:
    # 1. Remove self._get_subscription_models() calls → direct imports
    # 2. Remove self._active_user_subscription_filters() if it used User model
    # 3. Hardcode user_id=1 where needed
    # ... (full implementation copied from mixin files)
```

- [ ] **Step 2: Create content_repository.py**

Consolidate into one class `ContentRepository` the methods querying content tables:
- `get_highlights_for_episode`, `get_highlights_by_date_range`, `get_highlight_dates` (from analytics mixin)
- `get_daily_reports`, `get_daily_report_by_date`, `create_daily_report` (from content/workflow)
- `get_conversation_sessions`, `get_conversation_messages`, `create_conversation` (from content)
- `get_transcript`, `save_transcript` (transcript queries)

```python
"""Content repository — highlights, reports, conversations, transcripts."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.podcast.models import (
    EpisodeHighlight, HighlightExtractionTask,
    PodcastDailyReport, PodcastDailyReportItem,
    ConversationSession, PodcastConversation,
    PodcastEpisodeTranscript, TranscriptionTask,
)


class ContentRepository:
    """Repository for content-related queries."""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ... methods
```

- [ ] **Step 3: Update routes/dependencies.py**

Replace all repository class references to use the new consolidated classes:
- `PodcastEpisodeRepository` → `PodcastRepository`
- `PodcastPlaybackRepository` → `PodcastRepository`
- `PodcastQueueRepository` → `PodcastRepository`
- `PodcastSearchRepository` → `PodcastRepository`
- `PodcastStatsRepository` → `PodcastRepository`
- `PodcastSubscriptionRepository` → `PodcastRepository` (or keep separate SubscriptionRepository)
- `PodcastDailyReportRepository` → `ContentRepository`
- `PodcastSummaryRepository` → `PodcastRepository`

- [ ] **Step 4: Delete old repository files**

```bash
rm backend/app/domains/podcast/repositories/base.py
rm backend/app/domains/podcast/repositories/content.py
rm backend/app/domains/podcast/repositories/feed.py
rm backend/app/domains/podcast/repositories/analytics.py
rm backend/app/domains/podcast/repositories/playback_queue.py
rm backend/app/domains/podcast/repositories/daily_report.py
rm backend/app/domains/podcast/repositories/episode_query.py
rm backend/app/domains/podcast/repositories/playback.py
rm backend/app/domains/podcast/repositories/queue.py
rm backend/app/domains/podcast/repositories/stats_search.py
rm backend/app/domains/podcast/repositories/subscription_feed.py
rm backend/app/domains/podcast/repositories/transcription.py
rm backend/app/domains/podcast/repositories/subscription_repository.py
```

Update `backend/app/domains/podcast/repositories/__init__.py` to export only `PodcastRepository` and `ContentRepository`.

- [ ] **Step 5: Run tests**

```bash
cd backend && uv run pytest -x -q --ignore=tests/integration
```

- [ ] **Step 6: Commit**

```bash
git add -A backend/app/domains/podcast/repositories/ backend/app/domains/podcast/routes/dependencies.py && git commit -m "refactor(podcast): consolidate 13 repositories into 2 files"
```

---

### Task 4.2: Merge 14 podcast services into 6 files

**Files:**
- Merge: `subscription_service.py` + `episode_service.py` → `episode_service.py`
- Merge: `playback_service.py` + `queue_service.py` → `playback_service.py`
- Merge: `summary_service.py` + `highlight_service.py` + `daily_report_service.py` → `content_service.py`
- Merge: `transcription_workflow_service.py` + `transcription_runtime_service.py` + `transcription_schedule_service.py` → `transcription_service.py`
- Keep: `search_service.py`, `stats_service.py` (unchanged)
- Delete: `task_orchestration_service.py`
- Modify: `backend/app/domains/podcast/services/__init__.py`
- Modify: `backend/app/domains/podcast/routes/dependencies.py`

- [ ] **Step 1: Merge episode + subscription services**

Combine `episode_service.py` (512 lines) and `subscription_service.py` (809 lines) into a new `episode_service.py`:
- Keep `PodcastEpisodeService` class
- Add subscription CRUD methods from `PodcastSubscriptionService` as methods on `PodcastEpisodeService` (or as a separate `SubscriptionService` class in the same file)
- Update repository references to use consolidated `PodcastRepository`
- Update internal imports to use `app.domains.podcast.models` instead of `app.domains.subscription.models`

- [ ] **Step 2: Merge playback + queue services**

Combine `playback_service.py` (276 lines) and `queue_service.py` (135 lines) into a new `playback_service.py`:
- Keep `PodcastPlaybackService` class
- Add queue methods from `PodcastQueueService` as methods on `PodcastPlaybackService`

- [ ] **Step 3: Merge content services (summary + highlight + daily_report)**

Combine `summary_service.py` (678 lines), `highlight_service.py` (964 lines), and `daily_report_service.py` (483 lines) into `content_service.py`:
- Create `ContentService` class or keep as separate classes in one file
- Key classes to preserve: `PodcastSummaryGenerationService`, `SummaryWorkflowService`, `HighlightExtractionService`, `HighlightService`, `DailyReportService`

- [ ] **Step 4: Merge transcription services**

Combine `transcription_workflow_service.py` (587 lines), `transcription_runtime_service.py` (510 lines), and `transcription_schedule_service.py` (362 lines) into `transcription_service.py`:
- Keep `TranscriptionWorkflowService` as the main entry point
- Merge runtime and schedule methods into this class or as sibling classes

- [ ] **Step 5: Delete task_orchestration_service.py**

Delete `backend/app/domains/podcast/services/task_orchestration_service.py` (865 lines) — multi-user batch orchestration.

Find all callers:
```bash
cd backend && grep -rn "PodcastTaskOrchestrationService\|FeedSyncOrchestrator\|TranscriptionOrchestrator\|ReportOrchestrator\|MaintenanceOrchestrator" app/ --include="*.py" | grep -v __pycache__
```

For each task file that calls `PodcastTaskOrchestrationService`, redirect to the appropriate consolidated service directly:
- Feed sync tasks → call `PodcastEpisodeService` or `SubscriptionRepository` methods directly
- Transcription tasks → call `TranscriptionService` methods directly
- Report tasks → call `ContentService.generate_daily_reports()` directly
- Maintenance tasks → call repository methods directly

- [ ] **Step 6: Update services/__init__.py**

Replace all re-exports with the new consolidated services:
```python
from app.domains.podcast.services.episode_service import PodcastEpisodeService
from app.domains.podcast.services.playback_service import PodcastPlaybackService
from app.domains.podcast.services.content_service import (
    ContentService, SummaryWorkflowService, HighlightExtractionService, DailyReportService,
)
from app.domains.podcast.services.transcription_service import TranscriptionService
from app.domains.podcast.services.search_service import PodcastSearchService
from app.domains.podcast.services.stats_service import PodcastStatsService
```

- [ ] **Step 7: Update routes/dependencies.py**

Update all service factory functions to use the consolidated service classes.

- [ ] **Step 8: Run tests**

```bash
cd backend && uv run pytest -x -q --ignore=tests/integration
```

- [ ] **Step 9: Commit**

```bash
git add -A backend/app/domains/podcast/services/ backend/app/domains/podcast/routes/ && git commit -m "refactor(podcast): consolidate 14 services into 6, remove task orchestration"
```

---

### Task 4.3: Merge 6 AI services into 2 files

**Files:**
- Merge: `model_config_service.py` + `model_management_service.py` + `model_security_service.py` → `model_config_service.py`
- Merge: `text_generation_service.py` + `model_runtime_service.py` + `base_model_manager.py` → `text_generation_service.py`
- Delete: `model_management_service.py`, `model_security_service.py`, `model_runtime_service.py`, `base_model_manager.py`
- Modify: `backend/app/domains/ai/services/__init__.py`
- Modify: `backend/app/domains/ai/dependencies.py`

- [ ] **Step 1: Merge model config services**

Combine into `model_config_service.py`:
- `model_config_service.py` — model CRUD operations
- `model_management_service.py` — enable/disable, priority management
- `model_security_service.py` — API key encryption/decryption (uses `encrypt_data`/`decrypt_data` from core/security)

Keep `ModelConfigService` as the main class, add management and security methods.

- [ ] **Step 2: Merge text generation services**

Combine into `text_generation_service.py`:
- `text_generation_service.py` — high-level text generation
- `model_runtime_service.py` — model selection, fallback chain
- `base_model_manager.py` — shared model calling logic

Keep `TextGenerationService` as the main class, merge runtime and base logic.

- [ ] **Step 3: Update dependencies.py**

```bash
cd backend && grep -rn "from app.domains.ai.services" app/ --include="*.py" | grep -v __pycache__
```

Update all imports to use consolidated service names.

- [ ] **Step 4: Delete obsolete files**

```bash
rm backend/app/domains/ai/services/model_management_service.py
rm backend/app/domains/ai/services/model_security_service.py
rm backend/app/domains/ai/services/model_runtime_service.py
rm backend/app/domains/ai/services/base_model_manager.py
```

- [ ] **Step 5: Run tests**

```bash
cd backend && uv run pytest -x -q --ignore=tests/integration
```

- [ ] **Step 6: Commit**

```bash
git add -A backend/app/domains/ai/ && git commit -m "refactor(ai): consolidate 6 AI services into 2 files"
```

---

### Task 4.4: Update all test imports for consolidated services/repositories

**Files:**
- Modify: all test files in `backend/tests/` and `backend/app/domains/*/tests/`

- [ ] **Step 1: Find all test files referencing old service/repository names**

```bash
cd backend && grep -rn "PodcastEpisodeRepository\|PodcastPlaybackRepository\|PodcastQueueRepository\|PodcastSearchRepository\|PodcastStatsRepository\|PodcastDailyReportRepository\|PodcastSummaryRepository\|PodcastSubscriptionRepository\|PodcastTaskOrchestrationService" tests/ app/domains/ --include="*.py" | grep -v __pycache__ | grep test
```

- [ ] **Step 2: Update each test file**

For each test file found, update imports and class references:
- Old repository classes → `PodcastRepository` or `ContentRepository`
- Old service classes → consolidated service classes
- `PodcastTaskOrchestrationService` → remove or replace with direct service calls

- [ ] **Step 3: Run full test suite**

```bash
cd backend && uv run pytest -x -q --ignore=tests/integration
```

- [ ] **Step 4: Commit**

```bash
git add backend/tests/ backend/app/domains/ && git commit -m "test: update test imports for consolidated services and repositories"
```
