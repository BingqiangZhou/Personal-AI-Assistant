"""
Database configuration and session management.

This module provides production-ready PostgreSQL configuration for the Personal AI Assistant.

**Optimizations applied:**
- Connection pool health checks (pool_pre_ping) for container environments
- Automatic connection recycling to prevent stale sockets
- Optimized isolation level for read-heavy workload
- Fast failure detection (connect_timeout=10s)
- Application-level connection tagging for monitoring

**Connection Usage:**
- Typical: ~20-30 active connections for 5 domains
- High-load: Can overflow to ~60-80 connections
- Each domain should reuse sessions efficiently
"""

import logging
from collections.abc import AsyncGenerator
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.declarative import declarative_base

from app.core.config import settings


logger = logging.getLogger(__name__)

# Create async engine with production-ready configuration
engine = create_async_engine(
    settings.DATABASE_URL,
    # Core pool settings - optimized for podcast workloads
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    # Health check and connection validation (CRITICAL for long-running containers)
    pool_pre_ping=True,  # heartbeat connection before each borrow
    pool_recycle=settings.DATABASE_RECYCLE,  # recycle connections after configurable period
    # Performance optimizations
    echo=False,  # Disable SQL query logging to reduce noise
    future=True,  # SQLAlchemy 2.0 style
    isolation_level="READ COMMITTED",  # Optimized for read-heavy workload
    # Connection timeout settings - faster failure detection
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    connect_args={
        "server_settings": {
            "application_name": "personal-ai-assistant",
            "client_encoding": "utf8",
        },
        "timeout": settings.DATABASE_CONNECT_TIMEOUT,
    },
)

# Create session factory
async_session_factory = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

# Create declarative base
Base = declarative_base()


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async with async_session_factory() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db(run_metadata_sync: bool = False) -> None:
    """Initialize database tables.

    Note: PostgreSQL ENUM types may already exist from previous deployments.
    We handle this by creating them manually first with existence checks.
    """
    # Import all models to register relationships and metadata.
    # This MUST happen before any database operations to ensure SQLAlchemy
    # can properly resolve all relationships between models.
    from app.admin.models import (  # noqa: F401
        AdminAuditLog,
        BackgroundTaskRun,
        SystemSettings,
    )
    from app.domains.ai.models import AIModelConfig  # noqa: F401
    from app.domains.podcast.models import (  # noqa: F401
        PodcastConversation,
        PodcastEpisode,
        PodcastPlaybackState,
        TranscriptionTask,
    )
    from app.domains.subscription.models import (  # noqa: F401
        Subscription,
        SubscriptionCategory,
        SubscriptionCategoryMapping,
        SubscriptionItem,
        UserSubscription,
    )
    from app.domains.user.models import (  # noqa: F401
        PasswordReset,
        User,
        UserSession,
    )

    # Schema is managed by Alembic migrations - no manual ENUM creation needed
    async with engine.begin() as conn:
        if not run_metadata_sync:
            logger.info(
                "Database connectivity verified; "
                "schema is managed by Alembic migrations."
            )
            return

        # Optional compatibility path for environments that still need metadata sync.
        try:
            await conn.run_sync(Base.metadata.create_all, checkfirst=True)
            logger.info("Database tables initialized successfully via metadata sync")
        except (IntegrityError, ProgrammingError) as e:
            error_msg = str(e).lower()
            if "duplicate key" in error_msg and (
                "enum" in error_msg or "pg_type" in error_msg or "typname" in error_msg
            ):
                logger.warning(f"ENUM type conflict detected (non-critical): {e}")
                try:
                    result = await conn.execute(
                        text(
                            "SELECT 1 FROM information_schema.tables WHERE table_name = 'users'"
                        )
                    )
                    if result.first():
                        logger.info(
                            "Database tables verified to exist "
                            "(ignoring ENUM duplicate error)"
                        )
                    else:
                        raise ValueError("Tables do not exist after ENUM error") from e
                except Exception as verify_error:
                    logger.error(
                        f"Could not verify tables after ENUM error: {verify_error}"
                    )
                    raise e from verify_error
            else:
                logger.error(f"Failed to initialize database: {e}")
                raise


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()
    # Tiny delay to allow asyncpg/sqlalchemy background tasks to settle
    import asyncio

    await asyncio.sleep(0.1)


async def check_db_health() -> dict[str, Any]:
    """
    Check database connection health and performance metrics.
    Returns runtime health status for monitoring.
    """
    import time

    health_info = {
        "pool_size": engine.pool.size(),
        "checked_out": engine.pool.checkedout(),
        "overflow": engine.pool.overflow(),
        "connection_url": str(engine.url).replace(engine.url.password, "***"),
    }

    # Test minimal query
    start_time = time.time()
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1 as ping"))
            health_info["connect_time_ms"] = round((time.time() - start_time) * 1000, 2)
            health_info["status"] = "healthy"
            health_info["query_result"] = result.scalar()
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        health_info["status"] = "unhealthy"
        health_info["error"] = str(e)

    return health_info


def get_db_pool_snapshot() -> dict[str, Any]:
    """Return lightweight DB pool occupancy metrics without extra SQL queries."""
    pool_size = engine.pool.size()
    checked_out = engine.pool.checkedout()
    overflow = engine.pool.overflow()
    capacity = max(pool_size + overflow, 1)

    return {
        "pool_size": pool_size,
        "checked_out": checked_out,
        "overflow": overflow,
        "capacity": capacity,
        "occupancy_ratio": checked_out / capacity,
    }
