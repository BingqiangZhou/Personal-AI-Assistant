import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import validator
from pydantic_settings import BaseSettings


# Secret Key Management (moved here to avoid circular imports)
class SecretKeyManager:
    """Manages SECRET_KEY generation and storage - moved to config.py to avoid circular imports"""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.secret_key_file = self.data_dir / ".secret_key"
        self._secret_key: Optional[str] = None

    def ensure_data_dir(self):
        """Ensure data directory exists"""
        self.data_dir.mkdir(exist_ok=True, parents=True)

    def generate_secret_key(self) -> str:
        """Generate a new secure SECRET_KEY"""
        return secrets.token_urlsafe(48)

    def load_secret_key(self) -> str:
        """Load existing SECRET_KEY or generate new one"""
        if self._secret_key:
            return self._secret_key

        self.ensure_data_dir()

        # Try to load existing key
        if self.secret_key_file.exists():
            try:
                with open(self.secret_key_file) as f:
                    self._secret_key = f.read().strip()
                return self._secret_key
            except OSError:
                pass

        # Generate new key if none exists
        self._secret_key = self.generate_secret_key()
        self.save_secret_key(self._secret_key)
        return self._secret_key

    def save_secret_key(self, secret_key: str):
        """Save SECRET_KEY to file"""
        try:
            self.ensure_data_dir()
            with open(self.secret_key_file, 'w') as f:
                f.write(secret_key)
        except (OSError, PermissionError):
            # Silently fail if we can't write to disk (e.g., in Docker with read-only volume)
            # The secret key will still be available in memory for this session
            pass

    def get_secret_key(self) -> str:
        """Get the current SECRET_KEY"""
        return self.load_secret_key()


def get_or_generate_secret_key() -> str:
    """
    Get the SECRET_KEY for the application

    This function will:
    1. Load existing SECRET_KEY from file
    2. Generate new one if not exists
    3. Return the SECRET_KEY as a string
    """
    data_dir = os.getenv("DATA_DIR", "data")
    manager = SecretKeyManager(data_dir)
    return manager.get_secret_key()


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
    ALLOWED_HOSTS: list[str] = ["*"]

    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7  # Sliding session: refresh extends to 7 days from now
    ALGORITHM: str = "HS256"

    # Celery
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # Podcast Processing Limits
    MAX_PODCAST_SUBSCRIPTIONS: int = 999999  # Per user (unlimited)
    MAX_PODCAST_EPISODE_DOWNLOAD_SIZE: int = 500 * 1024 * 1024  # 500MB
    RSS_POLL_INTERVAL_MINUTES: int = 60  # Default polling interval

    # Privacy & Security
    LLM_CONTENT_SANITIZE_MODE: str = "standard"  # 'strict' | 'standard' | 'none'

    # Frontend URL
    FRONTEND_URL: str = "http://localhost:3000"

    # Email Configuration
    SMTP_SERVER: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USERNAME: Optional[str] = None
    SMTP_PASSWORD: Optional[str] = None
    SMTP_USE_TLS: bool = True
    FROM_EMAIL: str = "noreply@personalai.com"
    FROM_NAME: str = "Personal AI Assistant"
    EMAIL_RESET_TOKEN_EXPIRE_HOURS: int = 24
    ALLOWED_AUDIO_SCHEMES: list[str] = ["http", "https"]

    # External APIs
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_API_BASE_URL: str = "https://api.openai.com/v1"

    # File storage
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB
    UPLOAD_DIR: str = "uploads"

    # Transcription API Configuration
    TRANSCRIPTION_API_URL: str = "https://api.siliconflow.cn/v1/audio/transcriptions"
    TRANSCRIPTION_API_KEY: Optional[str] = None

    # Transcription File Processing Configuration
    TRANSCRIPTION_CHUNK_SIZE_MB: int = 10  # 10MB per chunk
    TRANSCRIPTION_TARGET_FORMAT: str = "mp3"
    TRANSCRIPTION_TEMP_DIR: str = "./temp/transcription"
    TRANSCRIPTION_STORAGE_DIR: str = "./storage/podcasts"

    # Transcription Concurrency Control
    TRANSCRIPTION_MAX_THREADS: int = 4  # Maximum concurrent transcription requests
    TRANSCRIPTION_QUEUE_SIZE: int = 100  # Maximum queue size for pending tasks

    # Admin Panel 2FA Configuration
    ADMIN_2FA_ENABLED: bool = True  # Admin panel 2FA toggle (default: enabled)

    # Assistant and Chat Configuration
    ASSISTANT_TITLE_TRUNCATION_LENGTH: int = 50  # Max length for auto-generated conversation titles
    ASSISTANT_TEST_PROMPT: str = "Hello, please respond with \"Test successful\"."

    # Pagination and Batch Processing
    PODCAST_EPISODE_BATCH_SIZE: int = 50  # Default batch size for episode processing
    PODCAST_RECENT_EPISODES_LIMIT: int = 3  # Number of recent episodes to fetch by default

    # ETag Configuration
    ETAG_ENABLED: bool = True  # Enable ETag caching for GET endpoints
    ETAG_DEFAULT_TTL: int = 300  # Default max-age for ETag responses (5 minutes)
    ETAG_CACHE_IN_REDIS: bool = True  # Cache ETags in Redis for cross-instance validation
    ETAG_REDIS_PREFIX: str = "etag:"  # Redis key prefix for ETag storage

    @validator("ALLOWED_HOSTS", pre=True)
    def assemble_cors_origins(cls, v):
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    @validator("ADMIN_2FA_ENABLED", pre=True)
    def parse_admin_2fa_enabled(cls, v):
        """Parse ADMIN_2FA_ENABLED from string to bool."""
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            return v.lower() in ("true", "1", "yes", "on")
        return bool(v)

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # Allow extra environment variables from Docker compose


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()

# Ensure SECRET_KEY is loaded on import
if settings.SECRET_KEY is None:
    settings.SECRET_KEY = get_or_generate_secret_key()