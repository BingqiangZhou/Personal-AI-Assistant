# Backend Audit Bugfixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all bugs identified in the backend audit — broken import, NoneType crash, exception leakage, N+1 query, missing Celery timeout handling, and failing feed parser tests.

**Architecture:** Targeted fixes in route handlers, service methods, and test mocks. No schema or migration changes.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy 2.x, Celery 5, aiohttp, pytest

---

### Task 1: Fix broken import in routes_highlights.py

**Files:**
- Modify: `backend/app/domains/podcast/routes/routes_highlights.py:90-91`

The import `from app.domains.podcast.tasks.highlight_extraction import extract_episode_highlights` references a non-existent module. The actual module is `app.domains.podcast.tasks.tasks_highlight`.

- [ ] **Step 1: Fix the import path**

Change line 90-91 from:
```python
from app.domains.podcast.tasks.highlight_extraction import (
    extract_episode_highlights,
)
```
to:
```python
from app.domains.podcast.tasks.tasks_highlight import (
    extract_episode_highlights,
)
```

- [ ] **Step 2: Verify the fix**

Run: `cd backend && uv run python -c "from app.domains.podcast.routes.routes_highlights import router; print('OK')"`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add backend/app/domains/podcast/routes/routes_highlights.py
git commit -m "fix(highlights): correct broken import path for extract_episode_highlights task"
```

---

### Task 2: Fix NoneType crash in subscription_service.get_subscription_details

**Files:**
- Modify: `backend/app/domains/podcast/services/subscription_service.py:383-385`

`ep.description` can be `None` (nullable column), causing `TypeError` when slicing.

- [ ] **Step 1: Add null-safe handling for description and ai_summary**

Replace lines 383-385:
```python
"description": ep.description[:100] + "..."
if len(ep.description) > 100
else ep.description,
```
with:
```python
"description": (ep.description or "")[:100] + "..."
if len(ep.description or "") > 100
else ep.description or "",
```

Also check lines 390-392 for `ep.ai_summary` — this already has `if ep.ai_summary and len(...)` which is safe, but make it consistent:
```python
"summary": (ep.ai_summary or "")[:200] + "..."
if ep.ai_summary and len(ep.ai_summary) > 200
else ep.ai_summary or "",
```

- [ ] **Step 2: Verify no ruff errors**

Run: `cd backend && uv run ruff check app/domains/podcast/services/subscription_service.py`
Expected: No errors (only pre-existing N806 in analytics.py if anything)

- [ ] **Step 3: Commit**

```bash
git add backend/app/domains/podcast/services/subscription_service.py
git commit -m "fix(subscription): handle None description/summary in get_subscription_details"
```

---

### Task 3: Fix exception details leaked in error responses

**Files:**
- Modify: `backend/app/domains/podcast/routes/routes_transcriptions.py`
- Modify: `backend/app/domains/podcast/routes/routes_episodes.py`
- Modify: `backend/app/domains/podcast/routes/routes_conversations.py`

Multiple endpoints include raw `{exc}` in HTTP response `detail`, leaking internal info.

**routes_transcriptions.py** — replace these `detail` strings:

| Line | Current | Replace with |
|------|---------|-------------|
| 96 | `f"Failed to start transcription: {exc}"` | `"Failed to start transcription"` |
| 202 | `f"Failed to get transcription: {exc}"` | `"Failed to get transcription"` |
| 239 | `f"Failed to delete transcription: {exc}"` | `"Failed to delete transcription task"` |
| 277 | `f"Failed to get transcription status: {exc}"` | `"Failed to get transcription status"` |
| 320 | `f"Failed to schedule transcription: {exc}"` | `"Failed to schedule transcription"` |
| 350 | `f"Failed to get transcript: {exc}"` | `"Failed to get transcript"` |
| 389 | `f"Failed to batch transcribe: {exc}"` | `"Failed to batch transcribe"` |
| 422 | `f"Failed to get transcription status: {exc}"` | `"Failed to get transcription status"` |
| 451 | `f"Failed to cancel transcription: {exc}"` | `"Failed to cancel transcription"` |
| 486 | `f"Failed to check new episodes: {exc}"` | `"Failed to check new episodes"` |
| 511 | `f"Failed to get pending transcriptions: {exc}"` | `"Failed to get pending transcriptions"` |

**routes_episodes.py** — line 86:
- Current: `detail=f"Failed to add subscription: {exc}"`
- Replace with: `detail="Failed to add subscription"`

**routes_conversations.py** — replace these:
| Line | Current | Replace with |
|------|---------|-------------|
| 74 | `f"Failed to list sessions: {exc}"` | `"Failed to list sessions"` |
| 113 | `f"Failed to create session: {exc}"` | `"Failed to create session"` |
| 146 | `f"Failed to delete session: {exc}"` | `"Failed to delete session"` |
| 197 | `f"Failed to get conversation history: {exc}"` | `"Failed to get conversation history"` |
| 240 | `f"Failed to send message: {exc}"` | `"Failed to send message"` |
| 286 | `f"Failed to clear conversation history: {exc}"` | `"Failed to clear conversation history"` |

- [ ] **Step 1: Fix routes_transcriptions.py**

Replace all 11 instances of `detail=f"...: {exc}"` with plain `detail="..."` strings (no f-string, no exc interpolation).

- [ ] **Step 2: Fix routes_episodes.py**

Replace `detail=f"Failed to add subscription: {exc}"` with `detail="Failed to add subscription"` on line 86.

- [ ] **Step 3: Fix routes_conversations.py**

Replace all 6 instances of `detail=f"...: {exc}"` with plain `detail="..."` strings.

- [ ] **Step 4: Verify ruff passes**

Run: `cd backend && uv run ruff check app/domains/podcast/routes/routes_transcriptions.py app/domains/podcast/routes/routes_episodes.py app/domains/podcast/routes/routes_conversations.py`
Expected: No errors

- [ ] **Step 5: Commit**

```bash
git add backend/app/domains/podcast/routes/routes_transcriptions.py backend/app/domains/podcast/routes/routes_episodes.py backend/app/domains/podcast/routes/routes_conversations.py
git commit -m "fix(security): remove internal exception details from HTTP error responses"
```

---

### Task 4: Fix N+1 query in highlight_service._claim_pending_highlight_episode_ids

**Files:**
- Modify: `backend/app/domains/podcast/services/highlight_service.py:636-658`

Current code loops over episode_ids executing individual queries. Replace with a single batch query.

- [ ] **Step 1: Replace the loop with batch query**

Replace lines 635-658:
```python
        claimed_ids: list[int] = []
        for episode_id in episode_ids:
            existing_stmt = select(HighlightExtractionTask).where(
                HighlightExtractionTask.episode_id == episode_id
            )
            existing_result = await self.db.execute(existing_stmt)
            existing_task = existing_result.scalar_one_or_none()

            if existing_task is None:
                task = HighlightExtractionTask(
                    episode_id=episode_id,
                    status="pending",
                    started_at=None,
                )
                self.db.add(task)
                claimed_ids.append(episode_id)
            elif existing_task.status == "in_progress":
                continue
            else:
                existing_task.status = "pending"
                existing_task.started_at = None
                existing_task.error_message = None
                claimed_ids.append(episode_id)
```

with:
```python
        # Batch fetch existing tasks for all episode_ids
        existing_stmt = select(HighlightExtractionTask).where(
            HighlightExtractionTask.episode_id.in_(episode_ids)
        )
        existing_result = await self.db.execute(existing_stmt)
        existing_tasks = {
            task.episode_id: task for task in existing_result.scalars().all()
        }

        claimed_ids: list[int] = []
        for episode_id in episode_ids:
            existing_task = existing_tasks.get(episode_id)

            if existing_task is None:
                task = HighlightExtractionTask(
                    episode_id=episode_id,
                    status="pending",
                    started_at=None,
                )
                self.db.add(task)
                claimed_ids.append(episode_id)
            elif existing_task.status == "in_progress":
                continue
            else:
                existing_task.status = "pending"
                existing_task.started_at = None
                existing_task.error_message = None
                claimed_ids.append(episode_id)
```

- [ ] **Step 2: Verify ruff passes**

Run: `cd backend && uv run ruff check app/domains/podcast/services/highlight_service.py`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add backend/app/domains/podcast/services/highlight_service.py
git commit -m "perf(highlights): replace N+1 query with batch query in claim_pending"
```

---

### Task 5: Add SoftTimeLimitExceeded handling to extract_episode_highlights task

**Files:**
- Modify: `backend/app/domains/podcast/tasks/tasks_highlight.py:64-108`

The task catches generic `Exception` but doesn't handle `SoftTimeLimitExceeded` gracefully like the sibling task `extract_pending_highlights` does.

- [ ] **Step 1: Add SoftTimeLimitExceeded import and handler**

Add import at the top of the file (near other imports):
```python
from celery.exceptions import SoftTimeLimitExceeded
```

Then in the `extract_episode_highlights` function, add a handler before the generic `except Exception` block (before line 90). The current structure is:

```python
    try:
        ...
        return result
    except Exception as exc:
        ...
```

Change to:
```python
    try:
        ...
        return result
    except SoftTimeLimitExceeded:
        logger.warning(
            "extract_episode_highlights timed out for episode_id=%s",
            episode_id,
        )
        log_task_run(
            task_name=task_name,
            queue_name=queue_name,
            status="timeout",
            started_at=started_at,
            finished_at=datetime.now(UTC),
            error_message="SoftTimeLimitExceeded",
            metadata={"episode_id": episode_id, "model_name": model_name},
        )
    except Exception as exc:
        ...
```

- [ ] **Step 2: Verify ruff passes**

Run: `cd backend && uv run ruff check app/domains/podcast/tasks/tasks_highlight.py`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add backend/app/domains/podcast/tasks/tasks_highlight.py
git commit -m "fix(celery): add SoftTimeLimitExceeded handling to extract_episode_highlights"
```

---

### Task 6: Fix failing feed parser tests

**Files:**
- Modify: `backend/app/core/tests/test_feed_parser.py:201-260`

The tests mock `client.get()` to return a plain `MagicMock`, but the actual code at `feed_parser.py:139` uses `async with client.get(url) as response:` (async context manager protocol). The mock needs to support `__aenter__`/`__aexit__`.

- [ ] **Step 1: Fix test_parse_feed_from_url_success (line 200-219)**

Change the mock setup from:
```python
mock_response = MagicMock()
mock_response.content = SAMPLE_RSS_FEED
mock_response.raise_for_status = MagicMock()

mock_client = AsyncMock()
mock_client.get = AsyncMock(return_value=mock_response)

parser._client = mock_client
```

to:
```python
mock_response = AsyncMock()
mock_response.content = SAMPLE_RSS_FEED
mock_response.raise_for_status = MagicMock()
mock_response.read = AsyncMock(return_value=SAMPLE_RSS_FEED)

mock_client = AsyncMock()
mock_context = AsyncMock()
mock_context.__aenter__ = AsyncMock(return_value=mock_response)
mock_context.__aexit__ = AsyncMock(return_value=False)
mock_client.get = MagicMock(return_value=mock_context)

parser._client = mock_client
```

- [ ] **Step 2: Fix test_parse_feed_from_url_offloads_parsing_to_thread (line 221-242)**

Same mock pattern change as Step 1. Change:
```python
mock_response = MagicMock()
mock_response.content = SAMPLE_RSS_FEED
mock_response.raise_for_status = MagicMock()

mock_client = AsyncMock()
mock_client.get = AsyncMock(return_value=mock_response)
parser._client = mock_client
```

to:
```python
mock_response = AsyncMock()
mock_response.content = SAMPLE_RSS_FEED
mock_response.raise_for_status = MagicMock()
mock_response.read = AsyncMock(return_value=SAMPLE_RSS_FEED)

mock_client = AsyncMock()
mock_context = AsyncMock()
mock_context.__aenter__ = AsyncMock(return_value=mock_response)
mock_context.__aexit__ = AsyncMock(return_value=False)
mock_client.get = MagicMock(return_value=mock_context)
parser._client = mock_client
```

- [ ] **Step 3: Fix test_parse_feed_from_url_network_error (line 244-260)**

The mock sets `side_effect` on `client.get`, but since `client.get` is used as `async with client.get(url)`, the side_effect needs to be on the context manager. Change:
```python
mock_client = AsyncMock()
mock_client.get = AsyncMock(
    side_effect=aiohttp.ClientError("Connection failed"),
)
parser._client = mock_client
```

to:
```python
mock_client = AsyncMock()
mock_context = AsyncMock()
mock_context.__aenter__ = AsyncMock(
    side_effect=aiohttp.ClientError("Connection failed"),
)
mock_context.__aexit__ = AsyncMock(return_value=False)
mock_client.get = MagicMock(return_value=mock_context)
parser._client = mock_client
```

- [ ] **Step 4: Also check test_parse_feed_from_url_http_error (line 262+)**

Check if the same pattern applies. If it uses `raise_for_status` to throw, the mock_response needs `raise_for_status` to raise. Read lines 262-290 to confirm and apply the same async context manager mock pattern if needed.

- [ ] **Step 5: Run the tests**

Run: `cd backend && uv run pytest app/core/tests/test_feed_parser.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/app/core/tests/test_feed_parser.py
git commit -m "fix(tests): fix feed parser test mocks for async context manager protocol"
```

---

### Task 7: Final verification

- [ ] **Step 1: Run full ruff check**

Run: `cd backend && uv run ruff check .`
Expected: Only pre-existing N806 warnings in analytics.py

- [ ] **Step 2: Run full test suite**

Run: `cd backend && uv run pytest -q`
Expected: All 411 tests pass (408 previous + 3 previously failing feed parser tests)

- [ ] **Step 3: Verify import chain works**

Run: `cd backend && uv run python -c "from app.main import create_application; print('OK')"`
Expected: `OK`
