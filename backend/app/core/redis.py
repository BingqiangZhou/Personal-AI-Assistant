from collections.abc import AsyncGenerator

import redis.asyncio as aioredis

from app.core.config import get_settings

settings = get_settings()

redis_pool = aioredis.ConnectionPool.from_url(
    str(settings.REDIS_URL),
    decode_responses=True,
    max_connections=20,
)

redis_client = aioredis.Redis(connection_pool=redis_pool)


async def get_redis() -> AsyncGenerator[aioredis.Redis, None]:
    yield redis_client


async def close_redis() -> None:
    await redis_client.aclose()
    await redis_pool.disconnect()
