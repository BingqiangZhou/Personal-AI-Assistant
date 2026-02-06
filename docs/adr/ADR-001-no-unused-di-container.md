# ADR-001: Remove Unused DI Container Framework

## Status
Accepted (2026-02-06)

## Context
- `app/core/container.py` existed but was not wired into route/runtime dependency resolution.
- `dependency-injector` added conceptual complexity without runtime value.
- The project already uses FastAPI `Depends` effectively for request-scoped construction.

## Decision
- Replace framework-based DI container implementation with lightweight provider functions.
- Keep `app/core/container.py` import path and helper function names for compatibility.
- Remove `dependency-injector` from `backend/pyproject.toml`.

## Consequences
- Reduced architectural noise and maintenance cost.
- Lower risk of divergence between “designed DI” and “actual runtime wiring”.
- If full DI framework becomes necessary later, re-introduction should be done with real routing integration and tests.
