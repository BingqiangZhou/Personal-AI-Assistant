# ADR-002: Route Thin, Service Thick

## Status
Accepted (2026-02-06)

## Context
- `app/domains/podcast/api/routes.py` had grown into a large mixed-responsibility module.
- Route layer repeatedly instantiated services and in some paths directly executed SQL.
- This made API behavior harder to audit and increased refactor risk.

## Decision
- Split podcast routes into submodules by responsibility:
  - `routes_subscriptions.py`
  - `routes_schedule.py`
  - `routes_episodes.py`
  - `routes_stats.py`
  - `routes_transcriptions.py`
  - `routes_conversations.py`
- Keep `app/domains/podcast/api/routes.py` as the aggregator entrypoint to preserve public routing.
- Move schedule SQL logic from routes to service layer via `PodcastScheduleService`.
- Introduce centralized podcast API dependency providers in `api/dependencies.py`.

## Consequences
- Route layer is now clearer and closer to protocol orchestration responsibilities.
- Business/data logic is more concentrated in services, improving testability.
- Public API paths and response schemas remain unchanged.
