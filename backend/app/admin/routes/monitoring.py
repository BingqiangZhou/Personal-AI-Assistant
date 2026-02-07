"""Admin monitoring routes module.

This module contains all routes related to system monitoring:
- Monitoring dashboard page
- System metrics API endpoints
- Background task monitoring
"""

import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.dependencies import admin_required
from app.admin.models import AdminAuditLog, BackgroundTaskRun
from app.admin.monitoring import get_monitor_service
from app.admin.routes._shared import get_templates
from app.core.database import get_db_session
from app.domains.ai.models import AIModelConfig
from app.domains.subscription.models import Subscription, SubscriptionStatus
from app.domains.user.models import User


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


# ==================== Monitoring Page ====================


@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_page(
    request: Request,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Display system monitoring dashboard."""
    try:
        # Get system metrics
        monitor = get_monitor_service()
        metrics = monitor.get_all_metrics()

        # Database statistics
        user_count_query = select(func.count()).select_from(User)
        user_count_result = await db.execute(user_count_query)
        user_count = user_count_result.scalar() or 0

        apikey_count_query = select(func.count()).select_from(AIModelConfig)
        apikey_count_result = await db.execute(apikey_count_query)
        apikey_count = apikey_count_result.scalar() or 0

        subscription_count_query = select(func.count()).select_from(Subscription)
        subscription_count_result = await db.execute(subscription_count_query)
        subscription_count = subscription_count_result.scalar() or 0

        # Active subscriptions
        active_subscription_query = select(func.count()).select_from(Subscription).where(Subscription.status == SubscriptionStatus.ACTIVE)
        active_subscription_result = await db.execute(active_subscription_query)
        active_subscription_count = active_subscription_result.scalar() or 0

        # Recent audit logs (last 24 hours)
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        recent_logs_query = select(func.count()).select_from(AdminAuditLog).where(AdminAuditLog.created_at >= yesterday)
        recent_logs_result = await db.execute(recent_logs_query)
        recent_logs_count = recent_logs_result.scalar() or 0

        # Failed operations (last 24 hours)
        failed_ops_query = select(func.count()).select_from(AdminAuditLog).where(
            AdminAuditLog.created_at >= yesterday,
            AdminAuditLog.status == "failed"
        )
        failed_ops_result = await db.execute(failed_ops_query)
        failed_ops_count = failed_ops_result.scalar() or 0

        # Recent audit logs for display
        recent_audit_logs_query = select(AdminAuditLog).order_by(AdminAuditLog.created_at.desc()).limit(10)
        recent_audit_logs_result = await db.execute(recent_audit_logs_query)
        recent_audit_logs = recent_audit_logs_result.scalars().all()

        return templates.TemplateResponse(
            "monitoring.html",
            {
                "request": request,
                "user": user,
                # Current time
                "current_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                # System info
                "hostname": metrics.system_info.hostname,
                "os_type": metrics.system_info.os_type,
                "os_version": metrics.system_info.os_version,
                "architecture": metrics.system_info.architecture,
                "uptime_seconds": metrics.system_info.uptime_seconds,
                "cpu_count": metrics.system_info.cpu_count,
                "current_users": metrics.system_info.current_users,
                # CPU metrics
                "cpu_percent": metrics.cpu.usage_percent,
                "per_cpu_percent": metrics.cpu.per_cpu_percent,
                "load_average_1min": metrics.cpu.load_average_1min,
                "load_average_5min": metrics.cpu.load_average_5min,
                "load_average_15min": metrics.cpu.load_average_15min,
                "context_switches": metrics.cpu.context_switches,
                "interrupts": metrics.cpu.interrupts,
                # Memory metrics
                "memory_percent": metrics.memory.percent,
                "memory_used_gb": metrics.memory.used_gb,
                "memory_total_gb": metrics.memory.total_gb,
                "memory_available_gb": metrics.memory.available_gb,
                "memory_buffered_gb": metrics.memory.buffered_gb,
                "memory_cached_gb": metrics.memory.cached_gb,
                "swap_percent": metrics.memory.swap_percent,
                "swap_used_gb": metrics.memory.swap_used_gb,
                "swap_total_gb": metrics.memory.swap_total_gb,
                # Disk metrics
                "disk_partitions": metrics.disk.partitions,
                # Network metrics
                "network_interfaces": metrics.network.interfaces,
                # Database stats
                "user_count": user_count,
                "apikey_count": apikey_count,
                "subscription_count": subscription_count,
                "active_subscription_count": active_subscription_count,
                "recent_logs_count": recent_logs_count,
                "failed_ops_count": failed_ops_count,
                "recent_audit_logs": recent_audit_logs,
                "messages": [],
            },
        )
    except Exception as e:
        logger.error(f"Monitoring page error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to load monitoring dashboard",
        )


# ==================== Monitoring API Endpoints ====================


@router.get("/api/monitoring/all")
async def get_all_metrics_api(
    user: User = Depends(admin_required),
):
    """Get all system metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_all_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get all metrics API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get system metrics",
        )


@router.get("/api/monitoring/system-info")
async def get_system_info_api(
    user: User = Depends(admin_required),
):
    """Get system basic information as JSON."""
    try:
        monitor = get_monitor_service()
        info = monitor.get_system_info()
        return JSONResponse(content=info.model_dump())
    except Exception as e:
        logger.error(f"Get system info API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get system info",
        )


@router.get("/api/monitoring/cpu")
async def get_cpu_metrics_api(
    user: User = Depends(admin_required),
):
    """Get CPU metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_cpu_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get CPU metrics API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get CPU metrics",
        )


@router.get("/api/monitoring/memory")
async def get_memory_metrics_api(
    user: User = Depends(admin_required),
):
    """Get memory metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_memory_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get memory metrics API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get memory metrics",
        )


@router.get("/api/monitoring/disk")
async def get_disk_metrics_api(
    user: User = Depends(admin_required),
):
    """Get disk metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_disk_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get disk metrics API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get disk metrics",
        )


@router.get("/api/monitoring/network")
async def get_network_metrics_api(
    user: User = Depends(admin_required),
):
    """Get network metrics as JSON."""
    try:
        monitor = get_monitor_service()
        metrics = monitor.get_network_metrics()
        return JSONResponse(content=metrics.model_dump())
    except Exception as e:
        logger.error(f"Get network metrics API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get network metrics",
        )


@router.get("/api/monitoring/tasks")
async def get_task_monitoring_api(
    limit: int = 50,
    user: User = Depends(admin_required),
    db: AsyncSession = Depends(get_db_session),
):
    """Get background task queue and execution statistics as JSON."""
    try:
        limit = max(1, min(limit, 200))

        total_stmt = select(func.count()).select_from(BackgroundTaskRun)
        total_result = await db.execute(total_stmt)
        total_runs = total_result.scalar_one()

        recent_stmt = (
            select(BackgroundTaskRun)
            .order_by(BackgroundTaskRun.started_at.desc())
            .limit(limit)
        )
        recent_result = await db.execute(recent_stmt)
        recent_runs = recent_result.scalars().all()

        status_stmt = (
            select(BackgroundTaskRun.status, func.count())
            .group_by(BackgroundTaskRun.status)
        )
        status_result = await db.execute(status_stmt)
        status_stats = {status: count for status, count in status_result.all()}

        queue_stmt = (
            select(BackgroundTaskRun.queue_name, func.count())
            .group_by(BackgroundTaskRun.queue_name)
        )
        queue_result = await db.execute(queue_stmt)
        queue_stats = {queue: count for queue, count in queue_result.all()}

        return JSONResponse(
            content={
                "total_runs": total_runs,
                "status_stats": status_stats,
                "queue_stats": queue_stats,
                "recent_runs": [
                    {
                        "id": run.id,
                        "task_name": run.task_name,
                        "queue_name": run.queue_name,
                        "status": run.status,
                        "started_at": run.started_at.isoformat() if run.started_at else None,
                        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                        "duration_ms": run.duration_ms,
                        "error_message": run.error_message,
                    }
                    for run in recent_runs
                ],
            }
        )
    except Exception as e:
        logger.error(f"Get task monitoring API error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get task monitoring metrics",
        )
