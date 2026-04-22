from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domains.podcast.models import ProcessingStatus


class SummaryCreate(BaseModel):
    episode_id: UUID
    content: str | None = None
    key_topics: list[str] | None = None
    highlights: list[str] | None = None
    model_used: str | None = None
    provider: str | None = None


class SummaryResponse(BaseModel):
    id: UUID
    episode_id: UUID
    status: ProcessingStatus
    key_topics: list[str] | dict | None = None
    highlights: list[str] | dict | None = None
    model_used: str | None = None
    provider: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SummaryDetail(SummaryResponse):
    content: str | None = None

    model_config = ConfigDict(from_attributes=True)
