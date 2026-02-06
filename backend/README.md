# Personal AI Assistant - Backend

FastAPI backend service for Personal AI Assistant.

## Stack

- FastAPI + SQLAlchemy async
- PostgreSQL
- Redis
- Celery
- Alembic
- Ruff + Pytest
- uv package manager

## Quick Start

```bash
cd backend
uv sync --extra dev
```

Create `.env` from `.env.example`, then run migrations:

```bash
uv run alembic upgrade head
```

Run API locally:

```bash
uv run uvicorn app.main:app --reload
```

Run Celery worker:

```bash
uv run celery -A app.core.celery_app:celery_app worker --loglevel=info
```

Run Celery beat:

```bash
uv run celery -A app.core.celery_app:celery_app beat --loglevel=info
```

## Quality Gates

Lint and format check:

```bash
uv run ruff check .
uv run ruff format .
```

Run tests:

```bash
uv run pytest
```

## API Notes

- Primary API prefix: `/api/v1`
- Podcast subscription API lives under: `/api/v1/subscriptions/podcasts*`
- Admin panel lives under: `/super/*`

## Docker Verification

```bash
cd docker
docker-compose up -d
curl http://localhost:8000/api/v1/health
```

## Project Layout

```text
backend/
|- alembic/
|- app/
|  |- admin/
|  |- core/
|  |- domains/
|  `- shared/
|- scripts/
|- tests/
|- pyproject.toml
`- requirements.txt
```
