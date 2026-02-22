"""Pydantic schemas for admin forms and validation."""

from pydantic import BaseModel, Field, field_validator


class AdminLoginForm(BaseModel):
    """Admin login form schema."""

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)


class APIKeyCreateForm(BaseModel):
    """API Key creation form schema."""

    name: str = Field(..., min_length=1, max_length=100, description="API Key name")
    description: str | None = Field(None, max_length=500, description="Description")


class SubscriptionEditForm(BaseModel):
    """RSS Subscription edit form schema."""

    title: str | None = Field(None, max_length=200)
    feed_url: str | None = Field(None, max_length=500)
    update_frequency: int | None = Field(None, ge=1, le=1440, description="Update frequency in minutes")

    @field_validator("feed_url")
    @classmethod
    def validate_url(cls, v):
        """Validate URL format."""
        if v and not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL must start with http:// or https://")
        return v
