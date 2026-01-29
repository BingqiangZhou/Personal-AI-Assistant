# CLAUDE.md

## Critical Commands

# Backend (uses uv, NOT pip)
cd backend && uv sync --extra dev
uv run alembic upgrade head
uv run uvicorn app.main:app --reload
uv run ruff check .    # NOT black/isort/flake8
uv run ruff format .
uv run pytest

# Frontend
cd frontend && flutter pub get
flutter test test/widget/  # Widget tests MANDATORY for pages

# Docker (backend MUST be tested this way)
cd docker && docker-compose up -d

## Project-Specific Rules

**Backend:**
- Use `uv` for package management, NEVER `pip install`
- Use `ruff` for linting/formatting (replaces black, isort, flake8)
- Backend MUST be verified via Docker, not direct uvicorn
- Follow async/await patterns for I/O

**Frontend:**
- Material 3 required: `useMaterial3: true` in ThemeData
- Use custom AdaptiveScaffoldWrapper (flutter_adaptive_scaffold deprecated)
- Widget tests are MANDATORY for page functionality
- Test on multiple screen sizes (mobile <600dp, desktop >840dp)

**API:**
- All endpoints prefixed with `/api/v1/`
- Bilingual error responses: `{message_en: str, message_zh: str}`

**Requirements:**
- Check `specs/active/` for existing requirements before implementing

## Gotchas (Common Mistakes)

| ❌ Wrong | ✅ Correct |
|---------|-----------|
| `pip install` | `uv add` or `uv sync` |
| black/isort/flake8 | `ruff check` / `ruff format` |
| `uvicorn` directly for testing | Docker for testing |
| Material 2 components | Material 3 only |
| Skip widget tests | Required for pages |

## Completion Criteria

A task is **NOT COMPLETE** until:
- ✅ Code compiles without errors
- ✅ Backend Docker containers start successfully
- ✅ Backend API responds correctly (`curl http://localhost:8000/api/v1/health`)
- ✅ All backend tests pass
- ✅ Frontend compiles and runs
- ✅ All frontend tests pass
- ✅ Modified functionality works end-to-end
