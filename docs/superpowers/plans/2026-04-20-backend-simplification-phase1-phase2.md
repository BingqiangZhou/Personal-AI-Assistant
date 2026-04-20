# Backend Simplification: Phase 1 & Phase 2 Implementation Plan

## Phase 1: Foundation — Config, Auth, Database, Redis

### Task 1.1: Simplify Config

**Files:**
- Modify: `backend/app/core/config.py`
- Test: `backend/tests/core/test_config.py` (new)

- [ ] **Step 1: Remove JWT fields, multi-user fields, and validators from `Settings`**

In `backend/app/core/config.py`, apply these edits:

Remove lines 71-74 (JWT section):
```python
    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
```

Remove line 90 (EMAIL_RESET_TOKEN_EXPIRE_HOURS):
```python
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 24
```

Remove line 136 (TASK_ORCHESTRATION_USER_BATCH_SIZE):
```python
    TASK_ORCHESTRATION_USER_BATCH_SIZE: int = 500
```

Remove lines 143-156 (_WEAK_PASSWORDS frozenset):
```python
    _WEAK_PASSWORDS: frozenset[str] = frozenset(
        {
            "mysecurepass2024",
            "password",
            "admin",
            "root",
            "postgres",
            "123456",
            "changeme",
            "default",
            "secret",
            "test",
        }
    )
```

Remove the validator at lines 200-205:
```python
    @field_validator("TASK_ORCHESTRATION_USER_BATCH_SIZE")
    @classmethod
    def validate_task_orchestration_user_batch_size(cls, v: int) -> int:
        if v < 1:
            raise ValueError("TASK_ORCHESTRATION_USER_BATCH_SIZE must be >= 1")
        return v
```

Add `API_KEY` field after `DEBUG`:
```python
    API_KEY: str = ""
```

Replace the `validate_production_config` method (lines 241-261) with:
```python
    def validate_production_config(self) -> list[str]:
        """Validate configuration for production environment."""
        issues = []
        if self.ENVIRONMENT == "production":
            if not self.SECRET_KEY:
                issues.append(
                    "SECRET_KEY should be explicitly set via environment variable in production"
                )
            if "*" in self.ALLOWED_HOSTS:
                issues.append(
                    "ALLOWED_HOSTS contains '*' which allows all origins. "
                    "Specify exact domains in production."
                )
            if not self.API_KEY:
                issues.append(
                    "API_KEY must be set in production for authentication"
                )
        return issues
```

Remove the `_extract_db_password` static method (lines 230-239) and the password-checking logic from `validate_production_config` that referenced it.

- [ ] **Step 2: Run tests**
```bash
cd backend && uv run ruff check app/core/config.py && uv run pytest tests/ -x -q --timeout=30 2>&1 | tail -20
```

- [ ] **Step 3: Commit**
```bash
git add backend/app/core/config.py && git commit -m "refactor(config): remove JWT/multi-user fields, add API_KEY

Remove ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS, ALGORITHM,
EMAIL_RESET_TOKEN_EXPIRE_HOURS, TASK_ORCHESTRATION_USER_BATCH_SIZE, _WEAK_PASSWORDS.
Add API_KEY field for single-user authentication. Simplify validate_production_config."
```

---

### Task 1.2: Delete JWT and Password Security Files

**Files:**
- Delete: `backend/app/core/security/jwt.py`
- Delete: `backend/app/core/security/password.py`
- Modify: `backend/app/core/security/__init__.py`
- Modify: `backend/app/core/security/encryption.py`

- [ ] **Step 1: Delete JWT and password modules**
```bash
rm backend/app/core/security/jwt.py backend/app/core/security/password.py
```

- [ ] **Step 2: Replace `core/security/__init__.py`**

Write the new content to `backend/app/core/security/__init__.py`:
```python
"""Security utilities for API key authentication and data encryption."""

import secrets

from app.core.security.encryption import (  # noqa: F401
    decrypt_data,
    encrypt_data,
    validate_export_password,
)


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)
```

- [ ] **Step 3: Simplify `core/security/encryption.py` — remove AES-256-GCM export/import**

Remove the functions `encrypt_data_with_password`, `decrypt_data_with_password`, and `validate_export_password` (lines 91-250). Also remove the `validate_export_password` import from `__init__.py` if you kept it above — actually remove it from `__init__.py` too since nothing will use it after admin export is simplified.

Final `backend/app/core/security/__init__.py`:
```python
"""Security utilities for API key authentication and data encryption."""

import secrets

from app.core.security.encryption import (  # noqa: F401
    decrypt_data,
    encrypt_data,
)


def generate_api_key() -> str:
    """Generate a secure API key."""
    return secrets.token_urlsafe(32)
```

Final `backend/app/core/security/encryption.py` — keep only `encrypt_data` and `decrypt_data` (lines 1-89). Remove lines 91-250 (`encrypt_data_with_password`, `decrypt_data_with_password`, `validate_export_password`).

- [ ] **Step 4: Run tests** (expect failures from removed modules — do not fix yet, just confirm no import errors at module level)
```bash
cd backend && uv run python -c "from app.core.security import encrypt_data, decrypt_data, generate_api_key; print('OK')"
```

- [ ] **Step 5: Commit**
```bash
git add -A backend/app/core/security/ && git commit -m "refactor(security): delete jwt.py and password.py, keep Fernet encryption only

Remove JWT token creation/verification and bcrypt password hashing.
Remove AES-256-GCM export/import encryption. Keep Fernet encrypt_data
and decrypt_data for AI API key storage. Add generate_api_key utility."
```

---

### Task 1.3: Rewrite Auth Module for API Key Authentication

**Files:**
- Modify: `backend/app/core/auth.py`
- Test: `backend/tests/core/test_auth.py` (new)

- [ ] **Step 1: Replace `backend/app/core/auth.py` with API key auth**

Write the new content:
```python
"""Authentication and request-level FastAPI dependencies.

Single-user mode: API key authentication via Authorization header or
X-API-Key header. User ID is hardcoded to 1.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, get_settings
from app.core.database import get_db_session


logger = logging.getLogger(__name__)

# Hardcoded single-user ID
SINGLE_USER_ID = 1


# ── Auth dependency ──────────────────────────────────────────────────────────


def _extract_api_key(request: Request) -> str | None:
    """Extract API key from Authorization: Bearer <key> or X-API-Key header."""
    authorization = request.headers.get("Authorization")
    if authorization:
        if authorization.startswith("Bearer "):
            return authorization[7:]
        return authorization

    x_api_key = request.headers.get("X-API-Key")
    if x_api_key:
        return x_api_key

    return None


async def require_api_key(request: Request) -> int:
    """Validate API key and return the hardcoded single-user ID.

    Raises HTTPException 401 if the key is missing or invalid.
    """
    settings = get_settings()

    # If no API_KEY configured (development), allow all requests
    if not settings.API_KEY:
        return SINGLE_USER_ID

    api_key = _extract_api_key(request)
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    return SINGLE_USER_ID


# ── Base dependencies ────────────────────────────────────────────────────────


async def get_db_session_dependency() -> AsyncGenerator[AsyncSession, None]:
    """Provide the request-scoped DB session through the provider layer."""
    async for db in get_db_session():
        yield db


async def get_redis_client():
    """Provide the shared Redis helper (process-level singleton)."""
    from app.core.redis import get_shared_redis

    return get_shared_redis()


def get_settings_dependency() -> Settings:
    """Provide cached application settings."""
    return get_settings()


# ── Compatibility aliases ────────────────────────────────────────────────────
# These provide backward compatibility during incremental migration.


async def get_token_user_id(user_id: int = Depends(require_api_key)) -> int:
    """Resolve the current user ID for podcast routes.

    Renamed conceptually to get_current_user_id, but keeps the old name
    so existing route signatures don't break during migration.
    """
    return user_id


# Alias for clarity in new code
get_current_user_id = get_token_user_id
```

- [ ] **Step 2: Update files that import removed symbols from `core/auth`**

The files that import `get_current_user`, `get_current_active_user`, `get_current_superuser`, or `get_authentication_service` from `core/auth`:

1. `backend/app/domains/user/api/dependencies.py` — entire file will be deleted in Phase 2
2. `backend/app/domains/subscription/api/dependencies.py` — update to use `get_token_user_id` instead of `get_current_active_user`

Read `backend/app/domains/subscription/api/dependencies.py` and replace any import of `get_current_active_user` with `get_token_user_id`. For now, just update the import line:

```bash
cd backend && grep -rn "get_current_active_user\|get_current_superuser\|get_authentication_service\|get_current_user" app/domains/ app/admin/ bootstrap/ --include="*.py"
```

For each file found, replace the old imports with:
- `get_current_user` -> `get_token_user_id` (or `require_api_key`)
- `get_current_active_user` -> `get_token_user_id`
- `get_current_superuser` -> `get_token_user_id`
- `get_authentication_service` -> remove (will be deleted with user domain)

Update `backend/app/domains/subscription/api/dependencies.py` — replace `get_current_active_user` import with `get_token_user_id`.

Update `backend/app/domains/podcast/routes/dependencies.py` — keep `get_token_user_id`, remove any other auth imports.

Update `backend/app/domains/ai/dependencies.py` — keep `get_db_session_dependency`, remove any auth-specific imports.

- [ ] **Step 3: Update `backend/tests/conftest.py` — replace `auth_headers` fixture**

Replace the `auth_headers` fixture (lines 97-132) with:
```python
@pytest_asyncio.fixture(scope="session")
async def auth_headers() -> dict[str, str]:
    """Return API key Authorization headers for test requests."""
    return {"Authorization": "Bearer test-api-key-for-tests"}
```

- [ ] **Step 4: Create `backend/tests/core/test_auth.py`**
```python
"""Tests for API key authentication in single-user mode."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.auth import SINGLE_USER_ID, require_api_key


@pytest.fixture
def app():
    """Create a minimal FastAPI app for auth testing."""
    _app = FastAPI()

    @_app.get("/test")
    async def protected(user_id: int = require_api_key):
        return {"user_id": user_id}

    return _app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestApiKeyAuth:
    """API key validation tests."""

    def test_no_key_returns_401_when_configured(self, client):
        with patch("app.core.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "configured-key"
            response = client.get("/test")
            assert response.status_code == 401
            assert "Authentication required" in response.json()["detail"]

    def test_wrong_key_returns_401(self, client):
        with patch("app.core.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "correct-key"
            response = client.get(
                "/test", headers={"Authorization": "Bearer wrong-key"}
            )
            assert response.status_code == 401
            assert "Invalid API key" in response.json()["detail"]

    def test_correct_bearer_key_returns_user_id(self, client):
        with patch("app.core.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "my-secret-key"
            response = client.get(
                "/test", headers={"Authorization": "Bearer my-secret-key"}
            )
            assert response.status_code == 200
            assert response.json()["user_id"] == SINGLE_USER_ID

    def test_x_api_key_header_works(self, client):
        with patch("app.core.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "my-secret-key"
            response = client.get(
                "/test", headers={"X-API-Key": "my-secret-key"}
            )
            assert response.status_code == 200
            assert response.json()["user_id"] == SINGLE_USER_ID

    def test_no_key_allowed_when_api_key_empty(self, client):
        with patch("app.core.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = ""
            response = client.get("/test")
            assert response.status_code == 200
            assert response.json()["user_id"] == SINGLE_USER_ID

    def test_single_user_id_is_one(self):
        assert SINGLE_USER_ID == 1
```

- [ ] **Step 5: Run tests**
```bash
cd backend && uv run pytest tests/core/test_auth.py -v
```

- [ ] **Step 6: Commit**
```bash
git add -A backend/app/core/auth.py backend/tests/core/test_auth.py backend/tests/conftest.py backend/app/domains/*/api/dependencies.py backend/app/domains/podcast/routes/dependencies.py backend/app/domains/ai/dependencies.py && git commit -m "refactor(auth): replace JWT auth with API key authentication

Rewrite core/auth.py to validate API key from Authorization/X-API-Key
headers against settings.API_KEY. Hardcode user_id to 1. Keep
get_db_session_dependency, get_redis_client, get_token_user_id as
compatibility aliases. Update downstream dependency files."
```

---

### Task 1.4: Simplify Database Module

**Files:**
- Modify: `backend/app/core/database.py`

- [ ] **Step 1: Remove Celery prefork worker logic, NullPool, and user model registration**

In `backend/app/core/database.py`:

Remove imports: `threading` (line 10), `NullPool` (line 25).

Remove globals: `_engine_lock` (line 41), `_worker_runtime_lock` (line 42), `_worker_runtimes` (line 43-46).

Replace `get_engine()` (lines 90-110) — remove thread-safe double-checked locking:
```python
def get_engine() -> AsyncEngine:
    """Get or create the async SQLAlchemy engine lazily."""
    global _engine, _engine_url

    database_url = get_settings().require_database_url()

    if _engine is not None and _engine_url == database_url:
        return _engine

    _engine = create_async_engine(
        database_url, **_build_engine_kwargs(database_url)
    )
    _engine_url = database_url
    return _engine
```

Remove `create_isolated_session_factory()` (lines 127-158), `_get_worker_runtime()` (lines 160-184), `worker_db_session()` (lines 187-195), `close_worker_db_runtimes()` (lines 198-206).

In `register_orm_models()` (lines 208-223), remove `"app.domains.user.models"` from the import tuple:
```python
def register_orm_models() -> None:
    """Import all ORM model modules exactly once to populate Base metadata."""
    global _orm_models_registered
    if _orm_models_registered:
        return

    for module in (
        "app.admin.models",
        "app.domains.ai.models",
        "app.domains.podcast.models",
        "app.domains.subscription.models",
    ):
        import_module(module)

    _orm_models_registered = True
```

In `init_db()`, update the error check from `'users'` table to a table that still exists, or remove the specific table check:
```python
                    result = await conn.execute(
                        text(
                            "SELECT 1 FROM information_schema.tables WHERE table_name = 'subscriptions'",
                        ),
                    )
```

In `close_db()` (lines 282-297), remove the `close_worker_db_runtimes()` call:
```python
async def close_db() -> None:
    """Dispose the lazily-created engine if it exists."""
    global _engine, _session_factory, _engine_url

    if _engine is None:
        return

    await _engine.dispose()
    _engine = None
    _session_factory = None
    _engine_url = None

    await asyncio.sleep(0.1)
```

Remove `import threading` from top-level imports.

- [ ] **Step 2: Run tests**
```bash
cd backend && uv run python -c "from app.core.database import get_engine, get_db_session, init_db, register_orm_models; print('OK')"
```

- [ ] **Step 3: Commit**
```bash
git add backend/app/core/database.py && git commit -m "refactor(database): remove Celery worker session caches and thread-safe locking

Remove NullPool, worker_db_session, create_isolated_session_factory,
close_worker_db_runtimes. Remove user model from register_orm_models.
Simplify get_engine to single-process usage."
```

---

### Task 1.5: Consolidate Redis Module into Single File

**Files:**
- Create: `backend/app/core/redis.py` (new single file)
- Delete: `backend/app/core/redis/` (entire directory: `__init__.py` and `client.py`)
- Delete: `backend/app/core/cache_ttl.py`
- Modify: any files importing `from app.core.redis` (should remain compatible if we keep the same public API)

- [ ] **Step 1: Create new `backend/app/core/redis.py`**

Write this file:
```python
"""Simplified Redis cache for single-user mode.

Usage:
    from app.core.redis import get_shared_redis

    redis = get_shared_redis()
    await redis.set("key", "value", ttl=3600)
"""

import asyncio
import hashlib
import logging
import threading
from contextlib import suppress
from datetime import datetime
from time import perf_counter
from typing import Any

import orjson
from redis import asyncio as aioredis
from redis.backoff import ExponentialBackoff
from redis.retry import Retry

from app.core.config import settings


logger = logging.getLogger(__name__)


class CacheTTL:
    """Cache TTL constants (seconds)."""

    DEFAULT: int = 1800           # 30 minutes
    SHORT: int = 60               # 1 minute
    LONG: int = 86400             # 1 day
    EPISODE_METADATA: int = 3600  # 1 hour
    LOCK_TIMEOUT: int = 30        # 30 seconds


def redis_json_default(obj: Any) -> Any:
    """Default JSON encoder for Redis — handles datetime objects."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


class RedisCache:
    """Thin wrapper over redis-py async client for single-user caching."""

    _health_check_interval_seconds = 30.0

    def __init__(self):
        self._client = None
        self._client_loop_token: int | None = None
        self._last_health_check_at = 0.0

    @staticmethod
    def _current_loop_token() -> int | None:
        try:
            return id(asyncio.get_running_loop())
        except RuntimeError:
            return None

    @staticmethod
    def _build_client() -> aioredis.Redis:
        return aioredis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True,
            max_connections=settings.REDIS_MAX_CONNECTIONS,
            retry=Retry(
                ExponentialBackoff(cap=10, base=1),
                3,
            ),
        )

    async def _ping_client(
        self, client: aioredis.Redis, *, timeout: float = 2.0
    ) -> bool:
        try:
            async with asyncio.timeout(timeout):
                await client.ping()
            return True
        except TimeoutError:
            logger.warning("Redis ping timed out after %.1f seconds", timeout)
            return False
        except Exception as e:
            logger.warning("Redis ping failed: %s", e)
            return False

    async def _get_client(self) -> aioredis.Redis:
        """Get Redis client with automatic reconnection and health checks."""
        current_loop_token = self._current_loop_token()

        if self._client is not None and self._client_loop_token != current_loop_token:
            old_client = self._client
            self._client = None
            self._client_loop_token = None
            self._last_health_check_at = 0.0
            with suppress(Exception):
                await old_client.close()

        if self._client is None:
            new_client = self._build_client()
            if not await self._ping_client(new_client):
                raise ConnectionError("Failed to connect to Redis after initial ping")
            self._client = new_client
            self._client_loop_token = current_loop_token
            self._last_health_check_at = perf_counter()
            return self._client

        now = perf_counter()
        if (now - self._last_health_check_at) < self._health_check_interval_seconds:
            return self._client

        if await self._ping_client(self._client):
            self._last_health_check_at = now
            return self._client

        logger.warning("Redis health check failed, attempting reconnection")
        old_client = self._client
        self._client = None

        with suppress(Exception):
            await old_client.close()

        max_retries = 3
        for attempt in range(max_retries):
            new_client = self._build_client()
            if await self._ping_client(new_client):
                self._client = new_client
                self._client_loop_token = current_loop_token
                self._last_health_check_at = perf_counter()
                logger.info("Redis reconnection successful on attempt %d", attempt + 1)
                return self._client

            if attempt < max_retries - 1:
                await asyncio.sleep(0.5 * (2**attempt))

        raise ConnectionError(
            f"Failed to reconnect to Redis after {max_retries} attempts"
        )

    async def close(self):
        """Close Redis connection."""
        if self._client:
            try:
                await self._client.close()
            finally:
                self._client = None
                self._client_loop_token = None
                self._last_health_check_at = 0.0

    async def check_health(self, timeout_seconds: float = 1.5) -> dict:
        """Return a compact Redis readiness payload."""
        try:
            async with asyncio.timeout(timeout_seconds):
                client = await self._get_client()
                await client.ping()
            return {"status": "healthy"}
        except TimeoutError:
            return {"status": "unhealthy", "error": "timeout"}
        except Exception as exc:
            return {"status": "unhealthy", "error": str(exc)}

    # ── Primitive operations ───────────────────────────────────────────────

    async def get(self, key: str) -> str | None:
        client = await self._get_client()
        return await client.get(key)

    async def set(self, key: str, value: str, ttl: int = CacheTTL.DEFAULT) -> bool:
        client = await self._get_client()
        return await client.setex(key, ttl, value)

    async def delete(self, key: str) -> bool:
        client = await self._get_client()
        result = await client.delete(key)
        return bool(result)

    async def exists(self, key: str) -> bool:
        client = await self._get_client()
        return bool(await client.exists(key))

    async def get_ttl(self, key: str) -> int:
        client = await self._get_client()
        return int(await client.ttl(key) or -1)

    async def set_if_not_exists(self, key: str, value: str, *, ttl: int | None = None) -> bool:
        client = await self._get_client()
        return bool(await client.set(key, value, ex=ttl, nx=True))

    # ── Pattern delete ─────────────────────────────────────────────────────

    async def delete_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern using SCAN."""
        client = await self._get_client()
        keys: list[str] = []
        async for key in client.scan_iter(match=pattern, count=100):
            keys.append(key)
        if not keys:
            return 0
        try:
            return int(await client.unlink(*keys) or 0)
        except Exception:
            return int(await client.delete(*keys) or 0)

    # ── JSON helpers ───────────────────────────────────────────────────────

    async def get_json(self, key: str) -> Any | None:
        client = await self._get_client()
        data = await client.get(key)
        if data:
            try:
                return orjson.loads(data)
            except orjson.JSONDecodeError:
                return None
        return None

    async def set_json(self, key: str, value: Any, ttl: int = CacheTTL.DEFAULT) -> bool:
        client = await self._get_client()
        try:
            json_str = orjson.dumps(value, default=redis_json_default).decode("utf-8")
            return bool(await client.setex(key, ttl, json_str))
        except (TypeError, ValueError):
            return False

    # ── Simple locks ───────────────────────────────────────────────────────

    async def acquire_lock(self, lock_name: str, expire: int = CacheTTL.LOCK_TIMEOUT) -> bool:
        client = await self._get_client()
        return bool(
            await client.set(f"lock:{lock_name}", "1", ex=expire, nx=True)
        )

    async def release_lock(self, lock_name: str) -> None:
        client = await self._get_client()
        await client.delete(f"lock:{lock_name}")


# Backward-compatible aliases
AppCache = RedisCache
PodcastRedis = RedisCache


# ── Module-level singleton ──────────────────────────────────────────────────

_shared_redis: RedisCache | None = None
_shared_redis_lock = threading.Lock()


def get_redis() -> RedisCache:
    """Create a new Redis cache helper."""
    return RedisCache()


def get_shared_redis() -> RedisCache:
    """Return a process-level shared Redis helper (thread-safe)."""
    global _shared_redis
    if _shared_redis is None:
        with _shared_redis_lock:
            if _shared_redis is None:
                _shared_redis = RedisCache()
    return _shared_redis


async def close_shared_redis() -> None:
    """Close the process-level shared Redis helper if it exists."""
    global _shared_redis
    if _shared_redis is None:
        return
    await _shared_redis.close()
    _shared_redis = None


__all__ = [
    "AppCache",
    "CacheTTL",
    "PodcastRedis",
    "RedisCache",
    "close_shared_redis",
    "get_redis",
    "get_shared_redis",
]
```

- [ ] **Step 2: Delete old Redis module and cache_ttl**
```bash
rm -rf backend/app/core/redis/
rm backend/app/core/cache_ttl.py
```

- [ ] **Step 3: Update all imports referencing old Redis API**

The old `AppCache` had domain-specific methods like `cache_get`, `cache_set`, `cache_get_json`, `cache_set_json`, `cache_delete`, `acquire_owned_lock`, `release_owned_lock`, etc. The new `RedisCache` has `get`, `set`, `get_json`, `set_json`, `delete`, `acquire_lock`, `release_lock`.

Search for usages and update:

```bash
cd backend && grep -rn "cache_get\|cache_set\|cache_delete\|cache_get_json\|cache_set_json\|acquire_owned_lock\|release_owned_lock\|from app.core.redis import\|from app.core.cache_ttl import" app/ --include="*.py"
```

For each file:
- `cache_get(key)` -> `get(key)`
- `cache_set(key, value, ttl=...)` -> `set(key, value, ttl=...)`
- `cache_delete(key)` -> `delete(key)`
- `cache_get_json(key)` -> `get_json(key)`
- `cache_set_json(key, value, ttl=...)` -> `set_json(key, value, ttl=...)`
- `acquire_owned_lock(...)` -> `acquire_lock(...)`
- `release_owned_lock(...)` -> `release_lock(...)`
- `from app.core.cache_ttl import CacheTTL` -> `from app.core.redis import CacheTTL`
- `from app.core.redis import get_shared_redis` -> stays the same (path unchanged)

Key files that use these methods (identified from the codebase):
- `bootstrap/lifecycle.py` — uses `acquire_owned_lock`, `release_owned_lock` -> change to `acquire_lock`, `release_lock`
- All domain services using `cache_get_json`, `cache_set_json`, etc.

- [ ] **Step 4: Run tests**
```bash
cd backend && uv run python -c "from app.core.redis import get_shared_redis, CacheTTL, AppCache, PodcastRedis; print('OK')"
```

- [ ] **Step 5: Commit**
```bash
git add -A backend/app/core/redis.py backend/app/core/redis/ backend/app/core/cache_ttl.py && git commit -m "refactor(redis): consolidate to single redis.py, remove domain-specific methods

Merge core/redis/__init__.py and core/redis/client.py into core/redis.py.
Delete core/cache_ttl.py. Remove AppCache domain-specific methods
(cache_get_with_lock, sorted_set_*, user stats, subscription cache, etc.).
Keep: get, set, delete, delete_pattern, get_json, set_json,
acquire_lock, release_lock, CacheTTL with 5 constants."
```

---

### Task 1.6: Remove Security Dependencies from pyproject.toml

**Files:**
- Modify: `backend/pyproject.toml`

- [ ] **Step 1: Remove `pyjwt`, `bcrypt`, `itsdangerous`, `email-validator` from dependencies**

In `backend/pyproject.toml`, remove these four lines from the `dependencies` array:
```
    "pyjwt>=2.12.1",
    "bcrypt>=5.0.0",
    "itsdangerous>=2.2.0",
    "email-validator>=2.3.0",
```

- [ ] **Step 2: Re-sync dependencies**
```bash
cd backend && uv sync --extra dev
```

- [ ] **Step 3: Commit**
```bash
git add backend/pyproject.toml backend/uv.lock && git commit -m "chore(deps): remove pyjwt, bcrypt, itsdangerous, email-validator

No longer needed after switching to API key auth and removing
user/password functionality."
```

---

### Task 1.7: Update Alembic env.py Mocks

**Files:**
- Modify: `backend/alembic/env.py`

- [ ] **Step 1: Remove JWT and password mocks, simplify MockSecurity**

In `backend/alembic/env.py`:

Remove from `MockConfig` class (lines 67-69):
```python
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    ALGORITHM = "HS256"
```

Remove from `MockSecurity` class (lines 109-119):
```python
    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta = None):
        return "mock_access_token"

    @staticmethod
    def create_refresh_token(data: dict, expires_delta: timedelta = None):
        return "mock_refresh_token"

    @staticmethod
    def verify_token(token: str, token_type: str = "access"):
        return {"sub": "1", "email": "test@example.com"}

    @staticmethod
    async def get_current_user(token: str, db):
        return None

    @staticmethod
    async def get_current_active_user(token: str, db):
        return None

    @staticmethod
    async def get_current_superuser(token: str, db):
        return None
```

Remove from `MockSecurity` class:
```python
    @staticmethod
    def verify_token_optional(token: str, token_type: str = "access"):
        return {"sub": "1", "email": "test@example.com"} if token else None

    @staticmethod
    async def get_token_from_request(
        authorization: str = None, api_key: str = Header(None)
    ):
        return "mock_token"

    @staticmethod
    def generate_password_reset_token(email: str):
        return "mock_reset_token"

    @staticmethod
    def verify_password_reset_token(token: str):
        return "test@example.com"
```

Remove the corresponding assignments to `mock_security_module`:
```python
mock_security_module.create_access_token = ...
mock_security_module.create_refresh_token = ...
mock_security_module.verify_token = ...
mock_security_module.get_current_user = ...
mock_security_module.get_current_active_user = ...
mock_security_module.get_current_superuser = ...
mock_security_module.verify_token_optional = ...
mock_security_module.get_token_from_request = ...
mock_security_module.generate_password_reset_token = ...
mock_security_module.verify_password_reset_token = ...
```

Remove the mock sub-modules (lines 193-207):
```python
_mock_jwt = types.ModuleType("app.core.security.jwt")
...
sys.modules["app.core.security.jwt"] = _mock_jwt

_mock_password = types.ModuleType("app.core.security.password")
...
sys.modules["app.core.security.password"] = _mock_password
```

Remove `from datetime import timedelta` import (line 7) and `from unittest.mock import AsyncMock` (line 11) if no longer needed.

Remove the `Header` mock class (lines 25-30) if no longer needed.

Keep `generate_api_key` and `generate_random_string` in MockSecurity since they are still used. Also keep `_mock_encryption`.

- [ ] **Step 2: Run tests**
```bash
cd backend && uv run python -c "import alembic.env" 2>&1 | head -5 || echo "Check alembic env loads"
```

- [ ] **Step 3: Commit**
```bash
git add backend/alembic/env.py && git commit -m "refactor(alembic): remove JWT and password mocks from env.py

Remove mock definitions for create_access_token, create_refresh_token,
verify_token, get_current_user, get_current_active_user, get_current_superuser,
verify_token_optional, get_token_from_request, password reset tokens,
and their sub-module registrations."
```

---

### Task 1.8: Rewrite Security Tests

**Files:**
- Modify: `backend/tests/core/test_security.py`

- [ ] **Step 1: Replace the entire test file**

Write `backend/tests/core/test_security.py`:
```python
"""Tests for the security module — API key generation, Fernet encryption."""

from __future__ import annotations

import pytest

from app.core.security import decrypt_data, encrypt_data, generate_api_key


class TestApiKeyGeneration:
    """API key generation tests."""

    def test_generates_url_safe_string(self):
        key = generate_api_key()
        assert isinstance(key, str)
        assert len(key) >= 40  # token_urlsafe(32) produces ~43 chars

    def test_generates_unique_keys(self):
        keys = {generate_api_key() for _ in range(10)}
        assert len(keys) == 10


class TestFernetEncryption:
    """Fernet symmetric encryption for AI API key storage."""

    def test_encrypt_decrypt_round_trip(self):
        plaintext = "sk-proj-abc123def456"
        encrypted = encrypt_data(plaintext)
        assert encrypted != plaintext
        assert decrypt_data(encrypted) == plaintext

    def test_encrypt_empty_string(self):
        assert encrypt_data("") == ""
        assert decrypt_data("") == ""

    def test_decrypt_invalid_ciphertext_raises(self):
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_data("not-valid-fernet-ciphertext==")

    def test_different_plaintexts_produce_different_ciphertexts(self):
        enc1 = encrypt_data("key-one")
        enc2 = encrypt_data("key-two")
        assert enc1 != enc2

    def test_encrypts_unicode(self):
        plaintext = "api-key-with-\u00e9\u4e2d\u6587"
        assert decrypt_data(encrypt_data(plaintext)) == plaintext

    def test_encrypts_long_string(self):
        plaintext = "x" * 10000
        assert decrypt_data(encrypt_data(plaintext)) == plaintext
```

- [ ] **Step 2: Run tests**
```bash
cd backend && uv run pytest tests/core/test_security.py -v
```

- [ ] **Step 3: Commit**
```bash
git add backend/tests/core/test_security.py && git commit -m "test(security): rewrite tests for API key gen and Fernet encryption

Remove all JWT token, password hashing, verify_token_optional,
get_token_from_request tests. Add tests for generate_api_key,
encrypt_data, decrypt_data."
```

---

### Task 1.9: Phase 1 Full Test Run

**Files:**
- None (verification only)

- [ ] **Step 1: Run full backend test suite**
```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -x -q 2>&1 | tail -30
```

- [ ] **Step 2: Fix any remaining import errors from removed modules**

Common patterns to fix:
- `from app.core.security import verify_password, get_password_hash` -> remove these imports
- `from app.core.security.jwt import ...` -> remove
- `from app.core.cache_ttl import CacheTTL` -> `from app.core.redis import CacheTTL`
- `from app.core.redis import safe_cache_get, safe_cache_write, safe_cache_invalidate` -> remove, inline the try/except pattern

- [ ] **Step 3: Run again until passing**
```bash
cd backend && uv run pytest --timeout=60 -x -q 2>&1 | tail -30
```

- [ ] **Step 4: Commit any fixes**
```bash
git add -A backend/ && git commit -m "fix: resolve remaining import errors after Phase 1 refactoring"
```

---

## Phase 2: Remove User Domain & Admin Auth Simplification

### Task 2.1: Delete User Domain

**Files:**
- Delete: `backend/app/domains/user/` (entire directory)
- Delete: `backend/app/domains/user/tests/test_auth_flows.py`
- Delete: `backend/tests/test_user_routes_error_handling.py`
- Delete: `backend/tests/integration/test_forgot_password_complete_flow.py`
- Modify: `backend/app/bootstrap/routers.py`

- [ ] **Step 1: Delete user domain and related tests**
```bash
rm -rf backend/app/domains/user/
rm -f backend/tests/test_user_routes_error_handling.py
rm -f backend/tests/integration/test_forgot_password_complete_flow.py
```

- [ ] **Step 2: Remove user router from `backend/app/bootstrap/routers.py`**

Remove line 18:
```python
from app.domains.user.api.routes import router as user_router
```

Remove lines 20-24:
```python
    app.include_router(
        user_router,
        prefix=f"{settings.API_V1_STR}/auth",
        tags=["authentication"],
    )
```

The file should now contain:
```python
"""Router registration bootstrap."""

from fastapi import FastAPI

from app.core.config import get_settings


def include_application_routers(app: FastAPI) -> None:
    """Register all HTTP routers without changing public API paths."""
    settings = get_settings()

    from app.admin.router import router as admin_router
    from app.domains.podcast.routes.routes import router as podcast_router
    from app.domains.podcast.routes.routes_subscriptions import (
        router as podcast_subscription_router,
    )
    from app.domains.subscription.api.routes import router as subscription_router

    app.include_router(
        subscription_router,
        prefix=f"{settings.API_V1_STR}/subscriptions",
        tags=["subscriptions"],
    )
    app.include_router(
        podcast_router,
        prefix=f"{settings.API_V1_STR}/podcasts",
        tags=["podcasts"],
    )
    app.include_router(
        podcast_subscription_router,
        prefix=f"{settings.API_V1_STR}/podcasts/subscriptions",
        tags=["podcast-subscriptions"],
    )
    app.include_router(
        admin_router,
        prefix=f"{settings.API_V1_STR}/admin",
        tags=["admin"],
    )
```

- [ ] **Step 3: Commit**
```bash
git add -A backend/app/domains/user/ backend/tests/test_user_routes_error_handling.py backend/tests/integration/test_forgot_password_complete_flow.py backend/app/bootstrap/routers.py && git commit -m "refactor: delete user domain and auth routes

Remove entire domains/user/ directory (models, repositories, services,
API routes, tests). Remove user router from bootstrap. Delete
test_user_routes_error_handling and test_forgot_password_complete_flow."
```

---

### Task 2.2: Simplify Admin Auth to API Key

**Files:**
- Modify: `backend/app/admin/auth.py`

- [ ] **Step 1: Replace `backend/app/admin/auth.py` with API key check**

Write the new content:
```python
"""Admin authentication — API key based.

Checks X-API-Key header or admin_session cookie against settings.API_KEY.
"""

import logging

from fastapi import Cookie, Depends, HTTPException, Request, status

from app.core.auth import get_db_session_dependency, require_api_key
from app.core.config import get_settings


logger = logging.getLogger(__name__)


class AdminAuthRequired:
    """Dependency to require admin authentication via API key."""

    async def __call__(
        self,
        request: Request,
        admin_session: str | None = Cookie(None),
    ) -> int:
        settings = get_settings()

        # Check X-API-Key header or Authorization header first
        auth_header = request.headers.get("Authorization")
        x_api_key = request.headers.get("X-API-Key")

        api_key = None
        if auth_header:
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]
            else:
                api_key = auth_header
        elif x_api_key:
            api_key = x_api_key
        elif admin_session:
            # Cookie-based: admin_session cookie contains the API key directly
            api_key = admin_session

        if not settings.API_KEY:
            # No API key configured — allow all (development mode)
            return 1

        if api_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )

        if api_key != settings.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
            )

        return 1


admin_required = AdminAuthRequired()
```

- [ ] **Step 2: Run tests**
```bash
cd backend && uv run python -c "from app.admin.auth import admin_required; print('OK')"
```

- [ ] **Step 3: Commit**
```bash
git add backend/app/admin/auth.py && git commit -m "refactor(admin): replace itsdangerous cookie auth with API key

Remove URLSafeTimedSerializer, IP binding, User model lookup.
Admin auth now checks X-API-Key header, Authorization header,
or admin_session cookie against settings.API_KEY."
```

---

### Task 2.3: Delete First-Run Middleware and Cache Warming

**Files:**
- Delete: `backend/app/admin/first_run.py`
- Delete: `backend/app/bootstrap/cache_warming.py`
- Modify: `backend/app/bootstrap/http.py`
- Modify: `backend/app/bootstrap/lifecycle.py`

- [ ] **Step 1: Delete files**
```bash
rm backend/app/admin/first_run.py backend/app/bootstrap/cache_warming.py
```

- [ ] **Step 2: Remove first-run middleware from `backend/app/bootstrap/http.py`**

Remove lines 34-36:
```python
    from app.admin.first_run import first_run_middleware

    app.middleware("http")(first_run_middleware)
```

The `configure_middlewares` function becomes:
```python
def configure_middlewares(app: FastAPI) -> None:
    """Register middleware stack."""
    settings = get_settings()

    app.add_middleware(RequestLoggingMiddleware, slow_threshold=5.0)
    logger.debug("Request logging middleware enabled")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_HOSTS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept", "X-Requested-With", "X-API-Key"],
    )
```

Note: Added `"X-API-Key"` to `allow_headers` since admin panel will now use this header.

- [ ] **Step 3: Remove cache warming from `backend/app/bootstrap/lifecycle.py`**

Remove import (line 9):
```python
from app.bootstrap.cache_warming import execute_cache_warmup
```

Remove cache warmup block (lines 126-140):
```python
    # Execute cache warm-up in background (non-blocking)
    session_factory = get_async_session_factory()
    warmup_task = asyncio.create_task(_run_cache_warmup_async(session_factory))
    warmup_task.add_done_callback(
        lambda task: (
            logger.error(
                "Cache warmup background task failed: %s",
                task.exception(),
                exc_info=task.exception(),
            )
            if task.exception()
            else None
        )
    )
```

Remove the `_run_cache_warmup_async` function (lines 188-210).

Replace `acquire_owned_lock`/`release_owned_lock` with `acquire_lock`/`release_lock` in the startup lock code:
```python
    startup_lock_acquired = False
    try:
        startup_lock_acquired = await get_shared_redis().acquire_lock(
            "startup:reset-stale-transcription-tasks",
            expire=300,
        )
        if startup_lock_acquired:
            ...
    finally:
        if startup_lock_acquired:
            await get_shared_redis().release_lock(
                "startup:reset-stale-transcription-tasks",
            )
```

Remove the mock authentication warning (lines 92-96):
```python
    if settings.ENVIRONMENT == "development" and settings.DEBUG:
        logger.warning(
            "SECURITY: Mock authentication is ENABLED (ENVIRONMENT=development, DEBUG=true). "
            "Never use in production!"
        )
```

Remove `get_async_session_factory` import from lifecycle.py since it was only used for cache warmup. Keep the import for `get_async_session_factory` if it is still needed for the stale transcription reset — check the code. It IS used at line 149 for `session_factory = get_async_session_factory()` so keep it.

- [ ] **Step 4: Run tests**
```bash
cd backend && uv run python -c "from app.bootstrap.http import configure_middlewares; from app.bootstrap.lifecycle import application_lifespan; print('OK')"
```

- [ ] **Step 5: Commit**
```bash
git add -A backend/app/admin/first_run.py backend/app/bootstrap/cache_warming.py backend/app/bootstrap/http.py backend/app/bootstrap/lifecycle.py && git commit -m "refactor(bootstrap): remove first-run middleware and cache warming

Delete admin/first_run.py and bootstrap/cache_warming.py.
Remove first_run_middleware registration from http.py.
Remove cache warmup background task from lifecycle.py.
Switch lifecycle startup lock to simple acquire_lock/release_lock."
```

---

### Task 2.4: Update Admin Routes — Remove User Model Imports

**Files:**
- Modify: `backend/app/admin/routes/dashboard.py`
- Modify: `backend/app/admin/routes/settings.py`
- Modify: `backend/app/admin/routes/apikeys.py`
- Modify: `backend/app/admin/routes/subscriptions.py`
- Modify: `backend/app/admin/services/dashboard_service.py`
- Modify: `backend/app/admin/services/subscriptions_service.py`
- Modify: `backend/app/admin/models.py`

- [ ] **Step 1: Update `backend/app/admin/routes/dashboard.py`**

Remove import:
```python
from app.domains.user.models import User
```

Change the `dashboard` function signature — `user: User = Depends(admin_required)` becomes `user_id: int = Depends(admin_required)`. Update template context to not pass `user`:
```python
@router.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user_id: int = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display admin dashboard."""
    from app.admin.services.dashboard_service import get_dashboard_context

    try:
        context = await get_dashboard_context(db)

        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "request": request,
                **context,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load dashboard",
        ) from e
```

- [ ] **Step 2: Update `backend/app/admin/routes/settings.py`**

Remove import:
```python
from app.domains.user.models import User
```

Replace every occurrence of `user: User = Depends(admin_required)` with `user_id: int = Depends(admin_required)`. Replace `_: User = Depends(admin_required)` with `_: int = Depends(admin_required)`. Replace `__` similarly.

The `save_audio_settings` and `save_frequency_settings` and `run_cleanup` service methods take a `user` argument — for now pass `user_id` instead. The service methods will need updating too but we'll handle that as a separate pass (they likely just use `user.username` for logging).

- [ ] **Step 3: Update `backend/app/admin/routes/apikeys.py`**

Remove import:
```python
from app.domains.user.models import User
```

Replace every `user: User = Depends(admin_required)` with `user_id: int = Depends(admin_required)`.

For the `test_apikey` handler that references `user.username`, pass a fixed string:
```python
        payload, status_code = await service.test_apikey_connection(
            api_url=api_url,
            api_key=api_key,
            model_type=model_type,
            name=name,
            key_id=key_id,
            username="admin",
        )
```

- [ ] **Step 4: Update `backend/app/admin/routes/subscriptions.py`**

Remove import:
```python
from app.domains.user.models import User
```

Replace every `user: User = Depends(admin_required)` with `user_id: int = Depends(admin_required)`.

For `test_subscription_url` that references `user.username`:
```python
        payload, status_code = await service.test_subscription_url(
            source_url=source_url,
            username="admin",
        )
```

- [ ] **Step 5: Update `backend/app/admin/services/dashboard_service.py`**

Remove import:
```python
from app.domains.user.models import User
```

Remove the `user_count` query:
```python
"""Admin dashboard service."""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domains.ai.models import AIModelConfig
from app.domains.subscription.models import Subscription


async def get_dashboard_context(db: AsyncSession) -> dict[str, int]:
    """Build dashboard statistics payloads."""
    apikey_count = int(
        (await db.execute(select(func.count()).select_from(AIModelConfig))).scalar()
        or 0,
    )
    subscription_count = int(
        (await db.execute(select(func.count()).select_from(Subscription))).scalar()
        or 0,
    )
    return {
        "apikey_count": apikey_count,
        "subscription_count": subscription_count,
    }
```

- [ ] **Step 6: Update `backend/app/admin/services/subscriptions_service.py`**

Remove import:
```python
from app.domains.user.models import User
```

Remove the `user_filter` logic in `get_page_context` that queries the User table (lines 90-105). Replace with an early return of empty context if `user_filter` is provided (since there are no users to filter by):
```python
        if user_filter and user_filter.strip():
            return self._empty_context(
                page=page,
                per_page=per_page,
                status_filter=status_filter,
                search_query=search_query,
                user_filter=user_filter,
            )
```

- [ ] **Step 7: Remove `BackgroundTaskRun` from `backend/app/admin/models.py`**

Remove the entire `BackgroundTaskRun` class (lines 42-65). Keep only `SystemSettings`.

- [ ] **Step 8: Run tests**
```bash
cd backend && uv run ruff check app/admin/ && uv run python -c "from app.admin.router import router; print('OK')"
```

- [ ] **Step 9: Commit**
```bash
git add -A backend/app/admin/ && git commit -m "refactor(admin): remove User model imports, use API key auth

Update all admin routes to use int user_id from admin_required
instead of User model. Remove user_count from dashboard. Remove
user_filter from subscriptions. Remove BackgroundTaskRun model."
```

---

### Task 2.5: Replace Admin Setup/Auth Routes with API Key Login

**Files:**
- Modify: `backend/app/admin/routes/setup_auth.py`
- Modify: `backend/app/admin/services/setup_auth_service.py`
- Modify: `backend/app/admin/dependencies.py`

- [ ] **Step 1: Replace `backend/app/admin/services/setup_auth_service.py`**

Simplify to remove all User-related methods. Keep only template helpers:
```python
"""Admin authentication service helpers (API key mode)."""

from fastapi import Request, status
from fastapi.responses import RedirectResponse


class AdminSetupAuthService:
    """Template rendering helpers for admin auth (simplified for API key mode)."""

    @staticmethod
    def build_template_response(
        *,
        templates,
        template_name: str,
        request: Request,
        messages: list[dict] | None = None,
        status_code: int = status.HTTP_200_OK,
        **context,
    ):
        """Render a template response."""
        return templates.TemplateResponse(
            request,
            template_name,
            {
                "request": request,
                "messages": messages or [],
                **context,
            },
            status_code=status_code,
        )

    @staticmethod
    def build_csrf_template_response(
        *,
        templates,
        template_name: str,
        request: Request,
        messages: list[dict] | None = None,
        status_code: int = status.HTTP_200_OK,
        **context,
    ):
        """Render a template (same as build_template_response without CSRF)."""
        return AdminSetupAuthService.build_template_response(
            templates=templates,
            template_name=template_name,
            request=request,
            messages=messages,
            status_code=status_code,
            **context,
        )
```

- [ ] **Step 2: Replace `backend/app/admin/routes/setup_auth.py`**

Replace with a simple login page that sets the API key as a cookie, and a logout route:
```python
"""Admin login/logout routes (API key mode)."""

import logging

from fastapi import APIRouter, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from app.admin.routes._shared import get_templates
from app.core.config import get_settings


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: str = None):
    """Display login page."""
    messages = [{"type": "error", "text": error}] if error else []
    from app.admin.services.setup_auth_service import AdminSetupAuthService

    return AdminSetupAuthService.build_csrf_template_response(
        templates=templates,
        template_name="login.html",
        request=request,
        messages=messages,
    )


@router.post("/login")
async def login(
    request: Request,
    api_key: str = Form(...),
):
    """Handle login with API key."""
    settings = get_settings()

    if not settings.API_KEY:
        # No API key configured — redirect directly to admin
        response = RedirectResponse(
            url="/api/v1/admin", status_code=status.HTTP_303_SEE_OTHER
        )
        return response

    if api_key != settings.API_KEY:
        from app.admin.services.setup_auth_service import AdminSetupAuthService

        return AdminSetupAuthService.build_csrf_template_response(
            templates=templates,
            template_name="login.html",
            request=request,
            messages=[{"type": "error", "text": "API key is incorrect"}],
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    response = RedirectResponse(
        url="/api/v1/admin", status_code=status.HTTP_303_SEE_OTHER
    )
    response.set_cookie(
        key="admin_session",
        value=api_key,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=30 * 60,
    )
    logger.info("Admin logged in via API key")
    return response


@router.post("/logout")
async def logout():
    """Handle logout."""
    response = RedirectResponse(
        url="/api/v1/admin/login", status_code=status.HTTP_303_SEE_OTHER
    )
    response.delete_cookie(key="admin_session")
    return response
```

- [ ] **Step 3: Run tests**
```bash
cd backend && uv run python -c "from app.admin.routes.setup_auth import router; print('OK')"
```

- [ ] **Step 4: Commit**
```bash
git add backend/app/admin/routes/setup_auth.py backend/app/admin/services/setup_auth_service.py && git commit -m "refactor(admin): replace user-based setup/login with API key login

Remove user creation, password verification, and session serialization.
Login now accepts API key via form, sets it as admin_session cookie.
Logout clears the cookie."
```

---

### Task 2.6: Update Downstream Importers of User Model

**Files:**
- Modify: `backend/app/domains/podcast/repositories/playback_queue.py`
- Modify: `backend/app/domains/podcast/tests/test_playback_rate_constraints.py`
- Modify: `backend/app/domains/subscription/tests/conftest.py`
- Modify: `backend/tests/test_subscription_repository_query_optimization.py`

- [ ] **Step 1: Remove User import from `backend/app/domains/podcast/repositories/playback_queue.py`**

Remove line 28:
```python
from app.domains.user.models import User
```

Search the file for any usage of `User` and replace with hardcoded `user_id=1` or remove. If `User` is not actually used in the function bodies (just imported), the removal is sufficient.

- [ ] **Step 2: Update `backend/app/domains/podcast/tests/test_playback_rate_constraints.py`**

Remove import:
```python
from app.domains.user.models import User
```

This test only checks model column/constraint metadata, so the User import is unused. Verify and remove.

- [ ] **Step 3: Update `backend/app/domains/subscription/tests/conftest.py`**

Remove imports:
```python
from app.core.security import get_password_hash
from app.domains.user.models import User, UserStatus
```

Remove `test_user` fixture, `another_user` fixture. Update `active_subscription` and `error_subscription` to not depend on `test_user` — hardcode `user_id=1`:

```python
    sub = await repo.create_subscription(1, sub_data)  # hardcoded user_id=1
```

Update `override_auth_dependencies` to use the new auth:
```python
    @pytest.fixture(autouse=True)
    def override_auth_dependencies(self):
        """Override authentication for routes requiring auth."""
        from app.core.auth import get_token_user_id, require_api_key

        app.dependency_overrides[require_api_key] = lambda: 1
        app.dependency_overrides[get_token_user_id] = lambda: 1
        try:
            yield
        finally:
            app.dependency_overrides.pop(require_api_key, None)
            app.dependency_overrides.pop(get_token_user_id, None)
```

- [ ] **Step 4: Update `backend/tests/test_subscription_repository_query_optimization.py`**

Remove any `from app.domains.user.models import User` import and any usage. Hardcode `user_id=1`.

- [ ] **Step 5: Run tests**
```bash
cd backend && uv run pytest --timeout=60 -x -q 2>&1 | tail -30
```

- [ ] **Step 6: Commit**
```bash
git add backend/app/domains/podcast/repositories/playback_queue.py backend/app/domains/podcast/tests/test_playback_rate_constraints.py backend/app/domains/subscription/tests/conftest.py backend/tests/test_subscription_repository_query_optimization.py && git commit -m "fix: remove User model imports from downstream files

Hardcode user_id=1 in podcast and subscription repositories/tests.
Update subscription test conftest to use API key auth override."
```

---

### Task 2.7: Rewrite Admin IP Binding Test

**Files:**
- Modify: `backend/tests/admin/test_admin_ip_binding.py`

- [ ] **Step 1: Rewrite the test for API key auth**

Read the existing file, then rewrite it to test the new admin auth behavior — API key validation instead of IP binding. Write:
```python
"""Tests for admin API key authentication."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.admin.auth import admin_required


@pytest.fixture
def app():
    _app = FastAPI()

    @_app.get("/admin/test")
    async def admin_endpoint(user_id: int = admin_required):
        return {"user_id": user_id}

    return _app


@pytest.fixture
def client(app):
    return TestClient(app)


class TestAdminApiKeyAuth:
    def test_valid_api_key_via_header(self, client):
        with patch("app.admin.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "admin-key-123"
            response = client.get(
                "/admin/test", headers={"X-API-Key": "admin-key-123"}
            )
            assert response.status_code == 200
            assert response.json()["user_id"] == 1

    def test_valid_api_key_via_bearer(self, client):
        with patch("app.admin.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "admin-key-123"
            response = client.get(
                "/admin/test", headers={"Authorization": "Bearer admin-key-123"}
            )
            assert response.status_code == 200

    def test_valid_api_key_via_cookie(self, client):
        with patch("app.admin.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "admin-key-123"
            response = client.get(
                "/admin/test", cookies={"admin_session": "admin-key-123"}
            )
            assert response.status_code == 200

    def test_invalid_api_key_returns_401(self, client):
        with patch("app.admin.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "correct-key"
            response = client.get(
                "/admin/test", headers={"X-API-Key": "wrong-key"}
            )
            assert response.status_code == 401

    def test_no_key_returns_401(self, client):
        with patch("app.admin.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = "configured-key"
            response = client.get("/admin/test")
            assert response.status_code == 401

    def test_no_key_allowed_when_empty(self, client):
        with patch("app.admin.auth.get_settings") as mock_settings:
            mock_settings.return_value.API_KEY = ""
            response = client.get("/admin/test")
            assert response.status_code == 200
```

- [ ] **Step 2: Run tests**
```bash
cd backend && uv run pytest tests/admin/test_admin_ip_binding.py -v
```

- [ ] **Step 3: Commit**
```bash
git add backend/tests/admin/test_admin_ip_binding.py && git commit -m "test(admin): rewrite IP binding test for API key auth

Replace itsdangerous/IP binding tests with API key header, bearer,
and cookie validation tests."
```

---

### Task 2.8: Phase 2 Full Test Run

**Files:**
- None (verification only)

- [ ] **Step 1: Run full backend test suite**
```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -x -q 2>&1 | tail -30
```

- [ ] **Step 2: Fix any remaining issues**

Search for any remaining references to the deleted modules:
```bash
cd backend && grep -rn "domains.user\|from app.domains.user\|UserStatus\|get_password_hash\|verify_password\|URLSafeTimedSerializer\|itsdangerous" app/ tests/ --include="*.py"
```

Fix each occurrence. Common patterns:
- `from app.domains.user.models import User` -> remove or hardcode user_id
- `from app.core.security import get_password_hash` -> remove
- `from app.core.redis import safe_cache_get` -> inline try/except

- [ ] **Step 3: Final test run**
```bash
cd backend && uv run ruff check . && uv run pytest --timeout=60 -q 2>&1 | tail -30
```

- [ ] **Step 4: Commit any fixes**
```bash
git add -A backend/ && git commit -m "fix: resolve remaining references after Phase 2 user domain removal"
```

---

## Summary of Changes

### Phase 1 (7 files modified, 2 files created, 2 files deleted)
| File | Action |
|------|--------|
| `backend/app/core/config.py` | Remove JWT/multi-user fields, add API_KEY |
| `backend/app/core/security/jwt.py` | DELETE |
| `backend/app/core/security/password.py` | DELETE |
| `backend/app/core/security/__init__.py` | Simplify to Fernet + generate_api_key |
| `backend/app/core/security/encryption.py` | Remove AES-256-GCM functions |
| `backend/app/core/auth.py` | Rewrite to API key auth (~70 lines) |
| `backend/app/core/database.py` | Remove worker sessions, user model registration |
| `backend/app/core/redis.py` | NEW single file (~250 lines) |
| `backend/app/core/redis/` | DELETE entire directory |
| `backend/app/core/cache_ttl.py` | DELETE |
| `backend/pyproject.toml` | Remove 4 dependencies |
| `backend/alembic/env.py` | Remove JWT/password mocks |
| `backend/tests/core/test_auth.py` | NEW |
| `backend/tests/core/test_security.py` | Rewrite for API key + Fernet |
| `backend/tests/conftest.py` | Simplify auth_headers fixture |

### Phase 2 (12 files modified, 0 files created, 6+ files deleted)
| File | Action |
|------|--------|
| `backend/app/domains/user/` | DELETE entire directory |
| `backend/app/admin/first_run.py` | DELETE |
| `backend/app/bootstrap/cache_warming.py` | DELETE |
| `backend/tests/test_user_routes_error_handling.py` | DELETE |
| `backend/tests/integration/test_forgot_password_complete_flow.py` | DELETE |
| `backend/app/admin/auth.py` | Rewrite to API key (~60 lines) |
| `backend/app/admin/routes/setup_auth.py` | Replace with API key login form |
| `backend/app/admin/services/setup_auth_service.py` | Simplify to template helpers only |
| `backend/app/admin/routes/dashboard.py` | Remove User import |
| `backend/app/admin/routes/settings.py` | Remove User import |
| `backend/app/admin/routes/apikeys.py` | Remove User import |
| `backend/app/admin/routes/subscriptions.py` | Remove User import |
| `backend/app/admin/services/dashboard_service.py` | Remove user_count |
| `backend/app/admin/services/subscriptions_service.py` | Remove User import |
| `backend/app/admin/models.py` | Remove BackgroundTaskRun |
| `backend/app/bootstrap/http.py` | Remove first-run middleware |
| `backend/app/bootstrap/lifecycle.py` | Remove cache warming, owned locks |
| `backend/app/bootstrap/routers.py` | Remove user router |
| `backend/tests/admin/test_admin_ip_binding.py` | Rewrite for API key auth |
| `backend/app/domains/podcast/repositories/playback_queue.py` | Remove User import |
| `backend/app/domains/subscription/tests/conftest.py` | Remove User fixtures |
