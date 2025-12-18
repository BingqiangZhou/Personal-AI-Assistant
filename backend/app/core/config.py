from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl, validator
import secrets


class Settings(BaseSettings):
    """Application settings."""

    # Basic
    PROJECT_NAME: str = "Personal AI Assistant"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: Optional[str] = None  # Will be loaded dynamically
    ENVIRONMENT: str = "development"

    # Database - Pool sizing adjusted for podcast-heavy workloads
    # Base calculation: 5 domains × 6 concurrent/domain × 2 buffer = 60 connections
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 20  # Increased from 10 - critical for RSS polling
    DATABASE_MAX_OVERFLOW: int = 40  # Increased from 20 - total 60 connections available

    # Database timeout settings
    DATABASE_POOL_TIMEOUT: int = 30  # Max wait for connection (seconds)
    DATABASE_RECYCLE: int = 3600  # Recycle connections after 1 hour
    DATABASE_CONNECT_TIMEOUT: int = 5  # Fast fail for connection issues

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # CORS
    ALLOWED_HOSTS: List[str] = ["*"]

    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # Podcast Processing Limits
    MAX_PODCAST_SUBSCRIPTIONS: int = 50  # Per user
    MAX_PODCAST_EPISODE_DOWNLOAD_SIZE: int = 500 * 1024 * 1024  # 500MB
    RSS_POLL_INTERVAL_MINUTES: int = 60  # Default polling interval

    # Privacy & Security
    LLM_CONTENT_SANITIZE_MODE: str = "standard"  # 'strict' | 'standard' | 'none'
    ALLOWED_AUDIO_SCHEMES: list[str] = ["http", "https"]

    # External APIs
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_API_BASE_URL: str = "https://api.openai.com/v1"

    # File storage
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    UPLOAD_DIR: str = "uploads"

    @validator("ALLOWED_HOSTS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()

# Ensure SECRET_KEY is loaded on import
if settings.SECRET_KEY is None:
    from app.core.security import get_or_generate_secret_key
    settings.SECRET_KEY = get_or_generate_secret_key()