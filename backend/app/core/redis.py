"""
Redis Helper - Simplified for Personal Use

Uses single Redis DB for all personal-scale operations:
- Cache: Podcast episode metadata
- Rate limiting: RSS polling protection
- Locks: Prevent duplicate processing
- Session: User data (if needed)
- Task locks: Podcast processing coordination

Recommended naming conventions:
- podcast:meta:{episode_id} - Episode metadata
- podcast:cache:{feed_url} - Feed cache
- podcast:lock:{action}:{id} - Distributed locks
- podcast:progress:{user}:{episode} - Listening progress
- podcast:summary:{episode}:{version} - AI summaries
"""

from typing import Optional
from redis import asyncio as aioredis
from app.core.config import settings


class PodcastRedis:
    """
    Simple Redis wrapper for podcast features
    """

    def __init__(self):
        self._client = None

    async def _get_client(self) -> aioredis.Redis:
        """Get Redis client instance"""
        if self._client is None:
            self._client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=20
            )
        # Ping to verify connection (async)
        try:
            await self._client.ping()
        except Exception:
            # Reconnect if ping fails
            self._client = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=5,
                socket_connect_timeout=5,
                retry_on_timeout=True,
                max_connections=20
            )
        return self._client

    # === Cache Operations ===

    async def cache_get(self, key: str) -> Optional[str]:
        """Get cached value"""
        client = await self._get_client()
        return await client.get(key)

    async def cache_set(self, key: str, value: str, ttl: int = 3600) -> bool:
        """Set cached value with TTL"""
        client = await self._get_client()
        return await client.setex(key, ttl, value)

    async def cache_delete(self, key: str) -> bool:
        """Delete cached value"""
        client = await self._get_client()
        return await client.delete(key)

    async def cache_hget(self, key: str, field: str) -> Optional[str]:
        """Get hash field"""
        client = await self._get_client()
        return await client.hget(key, field)

    async def cache_hset(self, key: str, mapping: dict, ttl: Optional[int] = None) -> int:
        """Set hash fields with optional TTL"""
        client = await self._get_client()
        result = await client.hset(key, mapping=mapping)
        if ttl:
            await client.expire(key, ttl)
        return result

    # === Convenience Methods ===

    async def get_episode_metadata(self, episode_id: int) -> Optional[dict]:
        """Get cached episode metadata"""
        key = f"podcast:meta:{episode_id}"
        data = await self.cache_hget(key, "*")
        return data

    async def set_episode_metadata(self, episode_id: int, metadata: dict) -> None:
        """Cache episode metadata (24 hours)"""
        key = f"podcast:meta:{episode_id}"
        await self.cache_hset(key, metadata, ttl=86400)

    async def get_cached_feed(self, feed_url: str) -> Optional[str]:
        """Get cached RSS feed"""
        key = f"podcast:cache:{hash(feed_url)}"
        return await self.cache_get(key)

    async def set_cached_feed(self, feed_url: str, xml_content: str) -> None:
        """Cache RSS feed (15 minutes)"""
        key = f"podcast:cache:{hash(feed_url)}"
        await self.cache_set(key, xml_content, ttl=900)

    async def get_ai_summary(self, episode_id: int, version: str = "v1") -> Optional[str]:
        """Get cached AI summary"""
        key = f"podcast:summary:{episode_id}:{version}"
        return await self.cache_get(key)

    async def set_ai_summary(self, episode_id: int, summary: str, version: str = "v1") -> None:
        """Cache AI summary (7 days)"""
        key = f"podcast:summary:{episode_id}:{version}"
        await self.cache_set(key, summary, ttl=604800)

    async def get_user_progress(self, user_id: int, episode_id: int) -> Optional[float]:
        """Get user listening progress"""
        key = f"podcast:progress:{user_id}:{episode_id}"
        progress = await self.cache_get(key)
        return float(progress) if progress else None

    async def set_user_progress(self, user_id: int, episode_id: int, progress: float) -> None:
        """Set user progress (30 days)"""
        key = f"podcast:progress:{user_id}:{episode_id}"
        await self.cache_set(key, str(progress), ttl=2592000)

    # === Lock Operations ===

    async def acquire_lock(self, lock_name: str, expire: int = 300) -> bool:
        """
        Acquire distributed lock
        Returns True if lock acquired
        """
        client = await self._get_client()
        key = f"podcast:lock:{lock_name}"
        return await client.set(key, "1", ex=expire, nx=True)

    async def release_lock(self, lock_name: str) -> None:
        """Release distributed lock"""
        client = await self._get_client()
        await client.delete(f"podcast:lock:{lock_name}")

    # === Rate Limiting ===

    async def check_rate_limit(self, user_id: int, action: str, limit: int, window: int) -> bool:
        """
        Simple rate limiting using Redis
        Returns True if allowed
        """
        client = await self._get_client()
        key = f"podcast:rate:{user_id}:{action}"
        current = await client.get(key)

        if current is None:
            await client.setex(key, window, 1)
            return True

        count = int(current)
        if count >= limit:
            return False

        await client.incr(key)
        return True

    async def close(self):
        """Close Redis connection"""
        if self._client:
            await self._client.close()


# Global singleton instance
_redis_instance = PodcastRedis()

async def get_redis() -> PodcastRedis:
    """Get global Redis instance"""
    return _redis_instance
