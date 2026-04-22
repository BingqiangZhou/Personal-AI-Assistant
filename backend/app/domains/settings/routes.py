import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.domains.settings.schemas import (
    ModelCreate,
    ModelListResponse,
    ModelResponse,
    ProviderCreate,
    ProviderListResponse,
    ProviderResponse,
    ProviderUpdate,
    TestConnectionResponse,
)
from app.domains.settings.service import SettingsService

router = APIRouter(tags=["settings"])
logger = logging.getLogger(__name__)


# ---- Providers ----

@router.get("/settings/providers", response_model=ProviderListResponse)
async def list_providers(
    db: AsyncSession = Depends(get_db),
) -> ProviderListResponse:
    service = SettingsService(db)
    providers = await service.list_providers()
    return ProviderListResponse(items=providers, total=len(providers))


@router.get("/settings/providers/{provider_id}", response_model=ProviderResponse)
async def get_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ProviderResponse:
    service = SettingsService(db)
    provider = await service.get_provider(provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider


@router.post("/settings/providers", response_model=ProviderResponse, status_code=201)
async def create_provider(
    data: ProviderCreate,
    db: AsyncSession = Depends(get_db),
) -> ProviderResponse:
    service = SettingsService(db)
    try:
        return await service.create_provider(data)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/settings/providers/{provider_id}", response_model=ProviderResponse)
async def update_provider(
    provider_id: UUID,
    data: ProviderUpdate,
    db: AsyncSession = Depends(get_db),
) -> ProviderResponse:
    service = SettingsService(db)
    provider = await service.update_provider(provider_id, data)
    if provider is None:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider


@router.delete("/settings/providers/{provider_id}", status_code=204)
async def delete_provider(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    service = SettingsService(db)
    deleted = await service.delete_provider(provider_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Provider not found")


@router.post("/settings/providers/{provider_id}/test", response_model=TestConnectionResponse)
async def test_provider_connection(
    provider_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> TestConnectionResponse:
    service = SettingsService(db)
    return await service.test_connection(provider_id)


# ---- Models ----

@router.get("/settings/models", response_model=ModelListResponse)
async def list_models(
    provider_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),
) -> ModelListResponse:
    service = SettingsService(db)
    models = await service.list_models(provider_id)
    return ModelListResponse(items=models, total=len(models))


@router.get("/settings/models/{model_id}", response_model=ModelResponse)
async def get_model(
    model_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> ModelResponse:
    service = SettingsService(db)
    model = await service.get_model(model_id)
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return model


class ModelUpdateRequest(BaseModel):
    model_name: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    is_default: bool | None = None


@router.post("/settings/models", response_model=ModelResponse, status_code=201)
async def create_model(
    data: ModelCreate,
    db: AsyncSession = Depends(get_db),
) -> ModelResponse:
    service = SettingsService(db)
    try:
        return await service.create_model(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.put("/settings/models/{model_id}", response_model=ModelResponse)
async def update_model(
    model_id: UUID,
    data: ModelUpdateRequest,
    db: AsyncSession = Depends(get_db),
) -> ModelResponse:
    service = SettingsService(db)
    model = await service.update_model(model_id, data.model_dump(exclude_none=True))
    if model is None:
        raise HTTPException(status_code=404, detail="Model not found")
    return model


@router.delete("/settings/models/{model_id}", status_code=204)
async def delete_model(
    model_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> None:
    service = SettingsService(db)
    deleted = await service.delete_model(model_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Model not found")
