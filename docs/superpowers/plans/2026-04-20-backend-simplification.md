# Backend Simplification — Single-User Mode Refactor

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor backend from multi-user SaaS architecture to simplified single-user personal app. Target: ~50% fewer files and lines of code.

**Architecture:** API Key auth, 2 domains (podcast + ai), 2 repositories, 6 podcast services + 2 AI services, single Celery queue, single Docker Compose for local and server.

**Tech Stack:** Python 3.11+, FastAPI, SQLAlchemy async, Redis, Celery, Docker Compose

**Design Spec:** `docs/superpowers/specs/2026-04-20-backend-simplification-design.md`

---

## Plan Structure

This plan is split into 4 sub-documents for parallel execution by agent teams:

| Phase | File | Tasks | Description |
|-------|------|-------|-------------|
| Phase 1+2 | [phase1-phase2.md](2026-04-20-backend-simplification-phase1-phase2.md) | 17 | Foundation: Config, Auth, DB, Redis + Remove User Domain, Admin Simplification |
| Phase 3 | [phase3-phase4.md](2026-04-20-backend-simplification-phase3-phase4.md) (Tasks 3.1-3.6) | 6 | Domain Consolidation: merge subscription/media/content into podcast |
| Phase 4 | [phase3-phase4.md](2026-04-20-backend-simplification-phase3-phase4.md) (Tasks 4.1-4.4) | 4 | Repository & Service Layer: 13 repos → 2, 14 services → 6 |
| Phase 5+6 | [phase5-phase6.md](2026-04-20-backend-simplification-phase5-phase6.md) | 14 | Celery Simplification + Bootstrap, Tests, Docker, Final Cleanup |

**Total: ~41 tasks across 6 phases**

---

## Execution Order

Phases must be executed sequentially because each depends on the previous:

```
Phase 1 (Foundation)
  ↓
Phase 2 (Remove User Domain)
  ↓
Phase 3 (Domain Consolidation)
  ↓
Phase 4 (Repo & Service Simplification)
  ↓
Phase 5 (Celery & Tasks)
  ↓
Phase 6 (Bootstrap, Tests, Docker, Cleanup)
```

Within each phase, tasks should be executed in order. Some tasks within a phase can be parallelized if they don't touch the same files.

---

## Task Summary

### Phase 1: Foundation (8 tasks)
1.1 — Simplify config (remove JWT/multi-user fields, add API_KEY)
1.2 — Delete JWT and password security files
1.3 — Rewrite auth module for API key authentication
1.4 — Simplify database module (remove Celery worker sessions)
1.5 — Consolidate Redis from 2 files into single redis.py (~250 lines)
1.6 — Remove 4 dependencies from pyproject.toml
1.7 — Update alembic/env.py mocks
1.8 — Rewrite security tests for API key + Fernet
1.9 — Full Phase 1 verification

### Phase 2: Remove User Domain (8 tasks)
2.1 — Delete entire user domain and related tests
2.2 — Simplify admin auth to API key
2.3 — Delete first-run middleware and cache warming
2.4 — Remove User model imports from all admin routes/services
2.5 — Replace admin setup/login with API key login
2.6 — Update downstream importers of User model
2.7 — Rewrite admin IP binding test for API key auth
2.8 — Full Phase 2 verification

### Phase 3: Domain Consolidation (6 tasks)
3.1 — Move subscription models into podcast/models.py
3.2 — Move subscription parsers into podcast/parsers/
3.3 — Move subscription repository into podcast
3.4 — Move media models and transcription into podcast
3.5 — Move content models into podcast, delete content/media/subscription domains
3.6 — Clean up shared/schemas.py

### Phase 4: Repository & Service Simplification (4 tasks)
4.1 — Merge 13 podcast repositories into 2 files
4.2 — Merge 14 podcast services into 6 files
4.3 — Merge 6 AI services into 2 files
4.4 — Update all test imports

### Phase 5: Celery & Tasks (5 tasks)
5.1 — Simplify runtime.py, delete _runlog.py
5.2 — Simplify celery_app.py (single queue, 4 beat tasks)
5.3 — Simplify all 6 task files (remove log_task_run, single_instance_task_lock)
5.4 — Update Celery test files
5.5 — Merge celery_worker + celery_beat in Docker Compose

### Phase 6: Final Cleanup (8 tasks)
6.1 — Simplify bootstrap/lifecycle.py (remove cache warming)
6.2 — Simplify bootstrap/http.py (remove first_run_middleware)
6.3 — Simplify bootstrap/routers.py (remove user/subscription routers)
6.4 — Simplify encryption.py (remove AES-256-GCM)
6.5 — Remove BackgroundTaskRun model
6.6 — Create Alembic migration (drop obsolete tables)
6.7 — Verify dependency cleanup
6.8 — Final validation (lint + tests + Docker smoke test)

---

## Agent Team Strategy

Recommended team structure for execution:

| Agent | Phases | Rationale |
|-------|--------|-----------|
| Agent A | Phase 1 + 2 | Foundation must be first, sequential |
| Agent B | Phase 3 + 4 | Domain consolidation, depends on Phase 2 |
| Agent C | Phase 5 + 6 | Celery and cleanup, depends on Phase 4 |

Agents execute sequentially (B waits for A, C waits for B). Each agent works through its tasks and runs tests at each checkpoint.
