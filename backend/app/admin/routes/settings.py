"""Admin settings routes module."""

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.admin.audit import log_admin_action
from app.admin.auth import admin_required
from app.admin.routes._shared import get_templates
from app.admin.services import AdminSettingsService
from app.core.providers import get_admin_settings_service
from app.domains.user.models import User


logger = logging.getLogger(__name__)

router = APIRouter()
templates = get_templates()


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(
    request: Request,
    user: User = Depends(admin_required),
):
    """Display system settings page."""
    try:
        return templates.TemplateResponse(
            "settings.html",
            {
                "request": request,
                "user": user,
                "messages": [],
            },
        )
    except Exception as exc:
        logger.error("Settings page error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to load settings page") from exc


@router.get("/settings/api/audio")
async def get_audio_settings(
    _: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Get audio processing settings as JSON."""
    try:
        return JSONResponse(content=await service.get_audio_settings())
    except Exception as exc:
        logger.error("Get audio settings error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to get audio settings") from exc


@router.post("/settings/api/audio")
async def update_audio_settings(
    request: Request,
    chunk_size_mb: int = Body(..., embed=True),
    max_concurrent_threads: int = Body(..., embed=True),
    user: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Update audio processing settings."""
    try:
        if not (5 <= chunk_size_mb <= 25):
            raise HTTPException(status_code=400, detail="chunk_size_mb must be between 5 and 25")
        if not (1 <= max_concurrent_threads <= 16):
            raise HTTPException(
                status_code=400,
                detail="max_concurrent_threads must be between 1 and 16",
            )

        await service.update_audio_settings(
            chunk_size_mb=chunk_size_mb,
            max_concurrent_threads=max_concurrent_threads,
        )
        await log_admin_action(
            db=service.db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="system_settings",
            resource_name="Audio processing settings",
            details={
                "chunk_size_mb": chunk_size_mb,
                "max_concurrent_threads": max_concurrent_threads,
            },
            request=request,
        )
        return JSONResponse(content={"success": True, "message": "Settings saved"})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Update audio settings error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update audio settings") from exc


@router.get("/settings/frequency")
async def get_frequency_settings(
    _: Request,
    __: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Get RSS subscription update frequency settings."""
    try:
        return JSONResponse(content=await service.get_frequency_settings())
    except Exception as exc:
        logger.error("Get frequency settings error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to get frequency settings") from exc


@router.post("/settings/frequency")
async def update_frequency_settings(
    request: Request,
    update_frequency: str = Body(..., embed=True),
    update_time: str | None = Body(None, embed=True),
    update_day: int | None = Body(None, embed=True),
    user: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Update RSS subscription update frequency settings."""
    try:
        valid_frequencies = ["HOURLY", "DAILY", "WEEKLY"]
        if update_frequency not in valid_frequencies:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid frequency. Must be one of: {valid_frequencies}",
            )
        if update_frequency in ["DAILY", "WEEKLY"] and not update_time:
            raise HTTPException(
                status_code=400,
                detail="update_time is required for DAILY and WEEKLY frequencies",
            )
        if update_frequency == "WEEKLY" and not update_day:
            raise HTTPException(
                status_code=400,
                detail="update_day is required for WEEKLY frequency",
            )
        if update_day is not None and not (1 <= update_day <= 7):
            raise HTTPException(status_code=400, detail="update_day must be between 1 and 7")

        settings_data, total_count = await service.update_frequency_settings(
            update_frequency=update_frequency,
            update_time=update_time,
            update_day=update_day,
        )
        await log_admin_action(
            db=service.db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="subscription_frequency",
            resource_name=f"All user subscriptions (affected {total_count})",
            details=settings_data,
            request=request,
        )
        return JSONResponse(
            content={
                "success": True,
                "message": f"RSS settings saved (updated {total_count} user-subscription mappings)",
            }
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Update frequency settings error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update frequency settings") from exc


@router.get("/settings/api/security")
async def get_security_settings(
    _: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Get security settings as JSON."""
    try:
        return JSONResponse(content=await service.get_security_settings())
    except Exception as exc:
        logger.error("Get security settings error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to get security settings") from exc


@router.post("/settings/api/security")
async def update_security_settings(
    request: Request,
    admin_2fa_enabled: bool = Body(..., embed=True),
    user: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Update security settings."""
    try:
        await service.update_security_settings(admin_2fa_enabled=admin_2fa_enabled)
        await log_admin_action(
            db=service.db,
            user_id=user.id,
            username=user.username,
            action="update",
            resource_type="security_settings",
            resource_name="Admin 2FA Settings",
            details={"admin_2fa_enabled": admin_2fa_enabled},
            request=request,
        )
        return JSONResponse(content={"success": True, "message": "Security settings saved"})
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Update security settings error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update security settings") from exc


@router.get("/settings/api/storage/info")
async def get_storage_info(
    _: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Get storage information as JSON."""
    try:
        return JSONResponse(content=await service.get_storage_info())
    except Exception as exc:
        logger.error("Get storage info error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to get storage information") from exc


@router.get("/settings/api/storage/cleanup/config")
async def get_cleanup_config(
    _: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Get auto cleanup configuration as JSON."""
    try:
        return JSONResponse(content=await service.get_cleanup_config())
    except Exception as exc:
        logger.error("Get cleanup config error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to get cleanup configuration") from exc


@router.post("/settings/api/storage/cleanup/config")
async def update_cleanup_config(
    request: Request,
    enabled: bool = Body(..., embed=True),
    user: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Update auto cleanup configuration."""
    try:
        result = await service.update_cleanup_config(enabled)
        if result.get("success"):
            await log_admin_action(
                db=service.db,
                user_id=user.id,
                username=user.username,
                action="update",
                resource_type="storage_settings",
                resource_name="Auto Cleanup Settings",
                details={"enabled": enabled},
                request=request,
            )
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Update cleanup config error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to update cleanup configuration") from exc


@router.post("/settings/api/storage/cleanup/execute")
async def execute_cleanup(
    request: Request,
    keep_days: int = Body(1, embed=True),
    user: User = Depends(admin_required),
    service: AdminSettingsService = Depends(get_admin_settings_service),
):
    """Execute manual cleanup."""
    try:
        result = await service.execute_cleanup(keep_days)
        await log_admin_action(
            db=service.db,
            user_id=user.id,
            username=user.username,
            action="execute",
            resource_type="storage_cleanup",
            resource_name="Manual Cache Cleanup",
            details={
                "keep_days": keep_days,
                "deleted_count": result.get("total", {}).get("deleted_count", 0),
                "freed_space": result.get("total", {}).get("freed_space_human", "0 B"),
            },
            request=request,
        )
        return JSONResponse(content=result)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Execute cleanup error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to execute cleanup") from exc
