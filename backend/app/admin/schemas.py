"""Pydantic schemas for admin forms and validation."""
from typing import Optional

from pydantic import BaseModel, Field, validator


class AdminLoginForm(BaseModel):
    """Admin login form schema."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class APIKeyCreateForm(BaseModel):
    """API Key creation form schema."""

    name: str = Field(..., min_length=1, max_length=100, description="API Key name")
    description: Optional[str] = Field(None, max_length=500, description="Description")


class SubscriptionEditForm(BaseModel):
    """RSS Subscription edit form schema."""

    title: Optional[str] = Field(None, max_length=200)
    feed_url: Optional[str] = Field(None, max_length=500)
    update_frequency: Optional[int] = Field(None, ge=1, le=1440, description="Update frequency in minutes")

    @validator("feed_url")
    def validate_url(cls, v):
        """Validate URL format."""
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v
