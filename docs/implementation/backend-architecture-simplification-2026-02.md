# Backend Architecture Simplification (2026-02)

## Scope
- Podcast API route decomposition.
- Route-to-service boundary clarification.
- Core/shared cleanup for currently unused abstraction layers.

## Key Structural Changes
- Podcast API was decomposed into sub-route modules:
  - `backend/app/domains/podcast/api/routes_subscriptions.py`
  - `backend/app/domains/podcast/api/routes_schedule.py`
  - `backend/app/domains/podcast/api/routes_episodes.py`
  - `backend/app/domains/podcast/api/routes_stats.py`
  - `backend/app/domains/podcast/api/routes_transcriptions.py`
  - `backend/app/domains/podcast/api/routes_conversations.py`
- `backend/app/domains/podcast/api/routes.py` is now an aggregator only.
- Added centralized dependency providers:
  - `backend/app/domains/podcast/api/dependencies.py`
- Added schedule service and moved schedule SQL out of route handlers:
  - `backend/app/domains/podcast/services/schedule_service.py`

## Core/Shared Cleanup
- `backend/app/core/container.py` converted to lightweight provider functions.
- Removed framework dependency declaration:
  - `dependency-injector` removed from `backend/pyproject.toml`.
- Shared layer kept only actively reused modules (`schemas`, `file_validation`, plus compatibility shims).

## Phase 2 (Facade Thinning)
- Added dedicated stats service:
  - `backend/app/domains/podcast/services/stats_service.py`
- `PodcastService.get_user_stats()` now delegates to `PodcastStatsService`.
- `PodcastService` private compatibility methods were classified:
  - kept with deprecation warning (still used by tasks/tests): `_generate_summary_task`, `_generate_summary`, `_call_llm_for_summary`, `_rule_based_summary`, `_calculate_listening_streak`
  - removed as unused wrappers in current codebase: subscription/internal summary helper wrappers and episode-count helper wrappers.

## Phase 3 (Core/Shared Simplification)
- Core DI remains lightweight provider functions:
  - `backend/app/core/container.py`
- Legacy feed parser/schema imports stay compatible via core shims:
  - `backend/app/core/feed_parser.py`
  - `backend/app/core/feed_schemas.py`
- Shim export completeness fixed:
  - `app.core.feed_parser` now re-exports `parse_feed_url` and `parse_feed_bytes` in addition to parser types.
- Shared layer remains minimal and runtime-used:
  - `backend/app/shared/schemas.py`
  - `backend/app/shared/file_validation.py`

## Compatibility Guarantees
- No API path changes under `/api/v1/podcasts/*`.
- No request/response schema contract changes intended.
- Backward-compatible router entrypoint remains `app.domains.podcast.api.routes:router`.

## Contract Baseline
- OpenAPI baseline exported to:
  - `docs/reports/openapi-baseline-2026-02-06.json`
- Diff helper:
  - `backend/scripts/check_openapi_diff.py`
- Acceptance report:
  - `docs/reports/backend-architecture-refactor-acceptance-2026-02-06.md`
