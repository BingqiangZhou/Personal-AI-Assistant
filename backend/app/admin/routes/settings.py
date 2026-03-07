"""Admin settings routes module."""

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse

from app.admin.auth import admin_required
from app.admin.routes._shared import get_templates, json_payload, render_admin_template
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
        return render_admin_template(
            templates=templates,
            template_name="settings.html",
            request=request,
            user=user,
            messages=[],
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
        return json_payload(await service.get_audio_settings())
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
        return json_payload(
            await service.save_audio_settings(
                request=request,
                user=user,
                chunk_size_mb=chunk_size_mb,
                max_concurrent_threads=max_concurrent_threads,
            )
        )
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
        return json_payload(await service.get_frequency_settings())
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
        return json_payload(
            await service.save_frequency_settings(
                request=request,
                user=user,
                update_frequency=update_frequency,
                update_time=update_time,
                update_day=update_day,
            )
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
        return json_payload(await service.get_security_settings())
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
        return json_payload(
            await service.save_security_settings(
                request=request,
                user=user,
                admin_2fa_enabled=admin_2fa_enabled,
            )
        )
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
        return json_payload(await service.get_storage_info())
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
        return json_payload(await service.get_cleanup_config())
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
        return json_payload(
            await service.save_cleanup_config(
                request=request,
                user=user,
                enabled=enabled,
            )
        )
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
        return json_payload(
            await service.run_cleanup(
                request=request,
                user=user,
                keep_days=keep_days,
            )
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Execute cleanup error: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to execute cleanup") from exc
