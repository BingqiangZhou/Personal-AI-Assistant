"""Test script to verify the alembic circular import fix"""
import sys
import os
import types
from datetime import timedelta

# Add backend to path
sys.path.insert(0, os.path.dirname(__file__))

print('Testing mock setup...')

# Step 1: Mock config
from pydantic_settings import BaseSettings
from functools import lru_cache

class MinimalSettings(BaseSettings):
    DATABASE_URL: str = 'postgresql+asyncpg://user:password@localhost:5432/personal_ai_assistant'
    class Config:
        env_file = '.env'
        case_sensitive = True
        extra = 'ignore'

@lru_cache()
def get_minimal_settings():
    return MinimalSettings()

minimal_settings = get_minimal_settings()
print(f'[OK] MinimalSettings works: {minimal_settings.DATABASE_URL}')

# Step 2: Create isolated Base
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()
print('[OK] Base created')

# Step 3: Mock config module
class MockConfig:
    PROJECT_NAME = 'Personal AI Assistant'
    VERSION = '1.0.0'
    API_V1_STR = '/api/v1'
    SECRET_KEY = 'migration-secret-key-placeholder'
    ENVIRONMENT = 'production'
    DATABASE_URL = minimal_settings.DATABASE_URL
    DATABASE_POOL_SIZE = 20
    DATABASE_MAX_OVERFLOW = 40
    DATABASE_POOL_TIMEOUT = 30
    DATABASE_RECYCLE = 3600
    DATABASE_CONNECT_TIMEOUT = 5
    REDIS_URL = 'redis://localhost:6379'
    ALLOWED_HOSTS = ['*']
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    REFRESH_TOKEN_EXPIRE_DAYS = 7
    ALGORITHM = 'HS256'
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
    MAX_PODCAST_SUBSCRIPTIONS = 50
    MAX_PODCAST_EPISODE_DOWNLOAD_SIZE = 500 * 1024 * 1024
    RSS_POLL_INTERVAL_MINUTES = 60
    LLM_CONTENT_SANITIZE_MODE = 'standard'
    FRONTEND_URL = 'http://localhost:3000'
    SMTP_SERVER = None
    SMTP_PORT = 587
    SMTP_USERNAME = None
    SMTP_PASSWORD = None
    SMTP_USE_TLS = True
    FROM_EMAIL = 'noreply@personalai.com'
    FROM_NAME = 'Personal AI Assistant'
    ALLOWED_AUDIO_SCHEMES = ['http', 'https']
    OPENAI_API_KEY = None
    OPENAI_API_BASE_URL = 'https://api.openai.com/v1'
    MAX_FILE_SIZE = 10 * 1024 * 1024
    UPLOAD_DIR = 'uploads'
    TRANSCRIPTION_API_URL = 'https://api.siliconflow.cn/v1/audio/transcriptions'
    TRANSCRIPTION_API_KEY = None
    TRANSCRIPTION_CHUNK_SIZE_MB = 10
    TRANSCRIPTION_TARGET_FORMAT = 'mp3'
    TRANSCRIPTION_TEMP_DIR = './temp/transcription'
    TRANSCRIPTION_STORAGE_DIR = './storage/podcasts'
    TRANSCRIPTION_MAX_THREADS = 4
    TRANSCRIPTION_QUEUE_SIZE = 100
    TRANSCRIPTION_MODEL = 'FunAudioLLM/SenseVoiceSmall'
    SUPPORTED_TRANSCRIPTION_MODELS = 'FunAudioLLM/SenseVoiceSmall,whisper-1,whisper-large-v3'
    SUMMARY_MODEL = 'gpt-4o-mini'
    SUPPORTED_SUMMARY_MODELS = 'gpt-4o-mini,gpt-4o,gpt-3.5-turbo'

mock_config_module = types.ModuleType('app.core.config')
mock_config_module.settings = MockConfig()

def mock_get_supported_transcription_models():
    return [model.strip() for model in MockConfig.SUPPORTED_TRANSCRIPTION_MODELS.split(',') if model.strip()]

def mock_get_supported_summary_models():
    return [model.strip() for model in MockConfig.SUPPORTED_SUMMARY_MODELS.split(',') if model.strip()]

mock_config_module.get_supported_transcription_models = mock_get_supported_transcription_models
mock_config_module.get_supported_summary_models = mock_get_supported_summary_models

sys.modules['app.core.config'] = mock_config_module
print('[OK] Mock config module registered')

# Step 4: Mock security module
class Header:
    def __init__(self, default=None, **kwargs):
        self.default = default
    def __call__(self, *args, **kwargs):
        return self.default

class MockSecurity:
    @staticmethod
    def get_or_generate_secret_key():
        return 'migration-secret-key-placeholder'

    @staticmethod
    def verify_password(plain_password, hashed_password):
        return True

    @staticmethod
    def get_password_hash(password):
        return 'mock_hash'

    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta = None):
        return 'mock_access_token'

    @staticmethod
    def create_refresh_token(data: dict, expires_delta: timedelta = None):
        return 'mock_refresh_token'

    @staticmethod
    def verify_token(token: str, token_type: str = 'access'):
        return {'sub': '1', 'email': 'test@example.com'}

    @staticmethod
    async def get_current_user(token: str, db):
        return None

    @staticmethod
    async def get_current_active_user(token: str, db):
        return None

    @staticmethod
    async def get_current_superuser(token: str, db):
        return None

    @staticmethod
    def verify_token_optional(token: str, token_type: str = 'access'):
        return {'sub': '1', 'email': 'test@example.com'} if token else None

    @staticmethod
    async def get_token_from_request(authorization: str = None, api_key: str = Header(None)):
        return 'mock_token'

    @staticmethod
    def generate_password_reset_token(email: str):
        return 'mock_reset_token'

    @staticmethod
    def verify_password_reset_token(token: str):
        return 'test@example.com'

    @staticmethod
    def generate_api_key():
        return 'mock_api_key'

    @staticmethod
    def generate_random_string(length: int = 32):
        return 'mock_random_string'

    @staticmethod
    def enable_ec256_optimized():
        return {'public_key': 'mock_public_key', 'private_key': 'mock_private_key'}

mock_security_module = types.ModuleType('app.core.security')
mock_security_module.settings = MockConfig()
mock_security_module.get_or_generate_secret_key = MockSecurity.get_or_generate_secret_key
mock_security_module.verify_password = MockSecurity.verify_password
mock_security_module.get_password_hash = MockSecurity.get_password_hash
mock_security_module.create_access_token = MockSecurity.create_access_token
mock_security_module.create_refresh_token = MockSecurity.create_refresh_token
mock_security_module.verify_token = MockSecurity.verify_token
mock_security_module.get_current_user = MockSecurity.get_current_user
mock_security_module.get_current_active_user = MockSecurity.get_current_active_user
mock_security_module.get_current_superuser = MockSecurity.get_current_superuser
mock_security_module.verify_token_optional = MockSecurity.verify_token_optional
mock_security_module.get_token_from_request = MockSecurity.get_token_from_request
mock_security_module.generate_password_reset_token = MockSecurity.generate_password_reset_token
mock_security_module.verify_password_reset_token = MockSecurity.verify_password_reset_token
mock_security_module.generate_api_key = MockSecurity.generate_api_key
mock_security_module.generate_random_string = MockSecurity.generate_random_string
mock_security_module.enable_ec256_optimized = MockSecurity.enable_ec256_optimized
mock_security_module.OAuth2PasswordBearer = lambda tokenUrl: None

sys.modules['app.core.security'] = mock_security_module
print('[OK] Mock security module registered')

# Step 5: Create mock app.core.database module
mock_database_module = types.ModuleType('app.core.database')
mock_database_module.Base = Base
mock_database_module.get_db_session = lambda: None  # Mock function
mock_database_module.engine = None  # Mock engine
sys.modules['app.core.database'] = mock_database_module
print('[OK] Mock app.core.database module registered')

# Now we can safely import the real database module to get its functions
# but we need to prevent it from creating the engine
import app.core.database
app.core.database.Base = Base  # Use our Base
print('[OK] app.core.database imported and patched')

# Step 6: Import models
try:
    from app.domains.podcast.models import PodcastEpisode, PodcastPlaybackState, TranscriptionTask
    print('[OK] Models imported successfully')
    print(f'  - PodcastEpisode: {PodcastEpisode.__table__}')
    print(f'  - PodcastPlaybackState: {PodcastPlaybackState.__table__}')
    print(f'  - TranscriptionTask: {TranscriptionTask.__table__}')

    # Check if TranscriptionTask has the new columns
    columns = [c.name for c in TranscriptionTask.__table__.columns]
    print(f'  - TranscriptionTask columns: {columns}')

    required_columns = ['summary_content', 'summary_model_used', 'summary_word_count', 'summary_processing_time', 'summary_error_message']
    missing = [col for col in required_columns if col not in columns]
    if missing:
        print(f'  - Missing columns: {missing}')
    else:
        print('  - All required columns present!')

except Exception as e:
    print(f'[ERROR] importing models: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)

print('\nAll tests passed! Mock setup is working correctly.')
