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
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from typing import AsyncGenerator, Dict, Any
from sqlalchemy import text

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
    echo=settings.ENVIRONMENT == "development",
    future=True,  # SQLAlchemy 2.0 style
    isolation_level="READ COMMITTED",  # Optimized for read-heavy workload

    # Connection timeout settings - faster failure detection
    pool_timeout=settings.DATABASE_POOL_TIMEOUT,
    connect_args={
        "server_settings": {
            "application_name": "personal-ai-assistant",
            "client_encoding": "utf8",
            "connect_timeout": str(settings.DATABASE_CONNECT_TIMEOUT)
        }
    }
)

# Create session factory
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
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


async def init_db() -> None:
    """Initialize database tables."""
    async with engine.begin() as conn:
        # Import all models here to ensure they are registered with Base
        from app.domains.subscription.models import Subscription, SubscriptionItem
        from app.domains.knowledge.models import KnowledgeBase, Document
        from app.domains.assistant.models import Conversation, Message
        from app.domains.multimedia.models import MediaFile, ProcessingJob

        # Create all tables
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Close database connections."""
    await engine.dispose()


async def check_db_health() -> Dict[str, Any]:
    """
    Check database connection health and performance metrics.
    Returns runtime health status for monitoring.
    """
    import time

    health_info = {
        "pool_size": engine.pool.size(),
        "checked_out": engine.pool.checkedout(),
        "overflow": engine.pool.overflow(),
        "connection_url": str(engine.url).replace(engine.url.password, "***")
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