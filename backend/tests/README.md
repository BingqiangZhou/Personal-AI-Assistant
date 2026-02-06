# Backend Tests

## Directory

```text
tests/
|- admin/
|- core/
|- integration/
|- podcast/
|- tasks/
|- performance/
|- test_route_snapshot.py
`- test_celery_config_snapshot.py
```

## Run Tests

```bash
cd backend
uv run pytest -s
```

Run selected suites:

```bash
uv run pytest tests/admin/
uv run pytest tests/tasks/
uv run pytest tests/test_route_snapshot.py
```

## Required Gates

```bash
uv run ruff check .
$env:DATABASE_URL='postgresql+asyncpg://user:pass@localhost:5432/test'; uv run pytest -s
```

## Snapshot Coverage

- `tests/test_route_snapshot.py`: `/api/v1/subscriptions/podcasts*` route snapshot.
- `tests/admin/test_admin_route_snapshot.py`: `/super/*` route snapshot.
- `tests/tasks/test_task_registry.py`: Celery task registration + routes + beat schedule consistency.
- `tests/tasks/test_transcription_task_flow.py`: transcription success/retry/lock behavior.
- `tests/tasks/test_summary_task_flow.py`: summary task success/retry behavior.
