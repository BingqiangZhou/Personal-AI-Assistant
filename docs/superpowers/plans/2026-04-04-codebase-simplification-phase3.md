# Phase 3: Docker Simplification — 7 → 5 Containers

> Continuation of codebase simplification plan. Phases 1-2 must be complete before starting.

**Goal:** Merge celery workers into one. Replace gunicorn with single uvicorn. Update Dockerfile and docker-compose. Result: 7 → 6 containers (2 celery workers merged into 1).

---

### Task 3.1: Update docker-compose.yml — merge celery workers

**Files:**
- Modify: `docker/docker-compose.yml`

- [ ] **Step 1: Read current docker-compose.yml**

- [ ] **Step 2: Replace `celery_worker_core` and `celery_worker_transcription` with single `celery_worker`**

```yaml
# New merged service:
celery_worker:
  build:
    context: ../backend
    dockerfile: Dockerfile
  command: celery -A app.core.celery_app worker --loglevel=info --concurrency=${CELERY_WORKERS:-2} -Q default,transcription
  environment:
    # Same env vars as both workers had
  depends_on:
    redis:
      condition: service_healthy
    postgres:
      condition: service_healthy
  volumes:
    # Union of both workers' volumes
  deploy:
    resources:
      limits:
        cpus: "2"
        memory: 2G
```

Remove both `celery_worker_core` and `celery_worker_transcription` service definitions.

- [ ] **Step 3: Verify YAML syntax**

```bash
cd docker && docker compose config --quiet
```

- [ ] **Step 4: Commit**

```bash
git add -A && git commit -m "refactor: merge celery workers in docker-compose (7→6 containers)"
```

---

### Task 3.2: Update Dockerfile — replace gunicorn with uvicorn

**Files:**
- Modify: `backend/Dockerfile`
- Modify: `backend/Dockerfile.cn` (if it uses gunicorn)

- [ ] **Step 1: Read current Dockerfile**

- [ ] **Step 2: Update CMD to use uvicorn directly**

```dockerfile
# Before:
CMD ["gunicorn", "app.main:app", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120"]

# After:
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--timeout-keep-alive", "90"]
```

Use 2 workers (sufficient for personal project with low concurrency).

- [ ] **Step 3: Update docker-compose.yml backend command**

```yaml
# Before:
command: gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000 --workers 4 --timeout 90 --graceful-timeout 30 --log-level info

# After:
command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2 --timeout-keep-alive 90 --log-level info
```

- [ ] **Step 4: Verify the build**

```bash
cd docker && docker compose build backend
```

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "refactor: replace gunicorn with uvicorn in Docker (6→5 effective containers)"
```

---

### Task 3.3: Test full Docker stack

- [ ] **Step 1: Start the stack**

```bash
cd docker && docker compose up -d
```

- [ ] **Step 2: Verify all services are healthy**

```bash
docker compose ps
curl http://localhost:8000/api/v1/health
```

Expected: 6 running services (postgres, redis, backend, celery_worker, celery_beat, nginx) — simplified from original 7 by merging 2 celery workers into 1.

- [ ] **Step 3: Verify celery worker handles all queues**

```bash
docker compose logs celery_worker | grep -i "ready"
```

Should show worker ready for both `default` and `transcription` queues.

- [ ] **Step 4: Tear down**

```bash
cd docker && docker compose down
```

---

<!-- Phase 4: Frontend Dead Code + Model Consolidation — see next file -->
