"""
Transcription State Manager - Redis-based caching and locking

Provides fast state management for podcast transcription tasks:
- Task locks to prevent duplicate processing
- Progress caching for efficient polling
- Ephemeral status storage with TTL
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from app.core.redis import PodcastRedis
from app.domains.podcast.models import TranscriptionStatus


logger = logging.getLogger(__name__)


class ProgressLogThrottle:
    """节流器，减少频繁的进度日志输出"""

    def __init__(self, min_interval_seconds: int = 5):
        """
        Args:
            min_interval_seconds: 最小日志间隔时间（秒）
        """
        self.min_interval = min_interval_seconds
        self._last_log_time: dict[str, float] = {}
        self._last_log_progress: dict[str, float] = {}

    def should_log(self, task_id: int, status: str, progress: float) -> bool:
        """
        判断是否应该记录日志

        Args:
            task_id: 任务ID
            status: 任务状态
            progress: 进度百分比

        Returns:
            True 如果应该记录日志
        """
        key = f"{task_id}_{status}"
        current_time = time.time()

        # 获取上次日志记录的时间和进度
        last_time = self._last_log_time.get(key, 0)
        last_progress = self._last_log_progress.get(key, -1)

        # 检查时间间隔（默认5秒）
        time_elapsed = current_time - last_time
        if time_elapsed < self.min_interval:
            return False

        # 检查进度变化（至少5%）
        progress_changed = abs(progress - last_progress) >= 5.0

        # 特殊进度点（0%, 50%, 100%）总是记录
        milestone = (progress < 1) or (49 <= progress <= 51) or (progress >= 99)

        if progress_changed or milestone:
            self._last_log_time[key] = current_time
            self._last_log_progress[key] = progress
            return True

        return False


# 全节气流器实例
_progress_throttle = ProgressLogThrottle(min_interval_seconds=5)


class TranscriptionStateKeys:
    """Redis key patterns for transcription state"""

    # Task lock: prevents duplicate processing for same episode
    TASK_LOCK = "podcast:transcription:lock:episode:{episode_id}"

    # Task progress: cached progress for fast polling (1 hour TTL)
    TASK_PROGRESS = "podcast:transcription:progress:{task_id}"

    # Episode-to-task mapping: find active task by episode_id (5 min TTL)
    EPISODE_TASK = "podcast:transcription:episode_task:{episode_id}"

    # Task status summary: lightweight status for dashboard (15 min TTL)
    TASK_STATUS = "podcast:transcription:status:{task_id}"


class TranscriptionStateManager:
    """
    Redis-based state manager for transcription tasks

    Provides:
    1. Distributed locks to prevent duplicate processing
    2. Fast progress caching for efficient polling
    3. Episode-to-task mapping for quick lookups
    4. Automatic cleanup with TTL
    """

    def __init__(self):
        self.redis = PodcastRedis()

    # === Redis Cache Access (convenience methods) ===

    async def cache_get(self, key: str) -> str | None:
        """
        Get value from Redis cache

        Args:
            key: Cache key

        Returns:
            Value if found, None otherwise
        """
        return await self.redis.cache_get(key)

    async def cache_set(self, key: str, value: str, ttl: int = 3600) -> None:
        """
        Set value in Redis cache

        Args:
            key: Cache key
            value: Value to store
            ttl: Time to live in seconds (default 1 hour)
        """
        await self.redis.cache_set(key, value, ttl=ttl)

    # === Lock Operations ===

    async def acquire_task_lock(
        self,
        episode_id: int,
        task_id: int,
        expire_seconds: int = 3600
    ) -> bool:
        """
        Acquire a lock for processing an episode

        Args:
            episode_id: Episode to lock
            task_id: Task ID that owns the lock
            expire_seconds: Lock expiration time (default 1 hour)

        Returns:
            True if lock acquired, False if already locked
        """
        key = TranscriptionStateKeys.TASK_LOCK.format(episode_id=episode_id)
        lock_value = str(task_id)

        try:
            acquired = await self.redis.acquire_lock(
                f"transcription:episode:{episode_id}",
                expire=expire_seconds
            )

            if acquired:
                # Store the task_id with the lock for verification
                client = await self.redis._get_client()
                await client.set(f"podcast:transcription:lock_value:{episode_id}", lock_value, ex=expire_seconds)
                logger.info(f"🔒 [LOCK] Acquired lock for episode {episode_id}, task {task_id}")
            else:
                # Check if our task already owns the lock
                client = await self.redis._get_client()
                existing = await client.get(f"podcast:transcription:lock_value:{episode_id}")
                if existing == lock_value:
                    logger.info(f"🔒 [LOCK] Task {task_id} already owns lock for episode {episode_id}")
                    return True
                logger.warning(f"🔒 [LOCK] Episode {episode_id} already locked by task {existing}")

            return acquired

        except Exception as e:
            logger.error(f"Failed to acquire lock for episode {episode_id}: {e}")
            return False

    async def release_task_lock(self, episode_id: int, task_id: int) -> bool:
        """
        Release a task lock

        Args:
            episode_id: Episode to unlock
            task_id: Task ID that owns the lock

        Returns:
            True if lock was released, False otherwise
        """
        try:
            # Verify we own the lock before releasing
            key = f"podcast:transcription:lock_value:{episode_id}"
            client = await self.redis._get_client()
            existing = await client.get(key)

            if existing and int(existing) != task_id:
                logger.warning(f"Cannot release lock for episode {episode_id}: owned by task {existing}, not {task_id}")
                return False

            await self.redis.release_lock(f"transcription:episode:{episode_id}")
            await client.delete(key)
            logger.info(f"🔓 [LOCK] Released lock for episode {episode_id}, task {task_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to release lock for episode {episode_id}: {e}")
            return False

    async def is_episode_locked(self, episode_id: int) -> int | None:
        """
        Check if an episode is locked and return the owning task ID

        Args:
            episode_id: Episode to check

        Returns:
            Task ID if locked, None if not locked
        """
        try:
            key = f"podcast:transcription:lock_value:{episode_id}"
            client = await self.redis._get_client()
            task_id_str = await client.get(key)
            return int(task_id_str) if task_id_str else None
        except Exception:
            return None

    # === Episode-to-Task Mapping ===

    async def set_episode_task(
        self,
        episode_id: int,
        task_id: int,
        ttl_seconds: int = 300
    ) -> None:
        """
        Map an episode to its active task ID

        Args:
            episode_id: Episode ID
            task_id: Active transcription task ID
            ttl_seconds: Cache TTL (default 5 minutes)
        """
        key = TranscriptionStateKeys.EPISODE_TASK.format(episode_id=episode_id)
        await self.redis.cache_set(key, str(task_id), ttl=ttl_seconds)
        logger.debug(f"Mapped episode {episode_id} to task {task_id}")

    async def get_episode_task(self, episode_id: int) -> int | None:
        """
        Get the active task ID for an episode

        Args:
            episode_id: Episode ID

        Returns:
            Task ID if found, None otherwise
        """
        key = TranscriptionStateKeys.EPISODE_TASK.format(episode_id=episode_id)
        task_id_str = await self.redis.cache_get(key)
        return int(task_id_str) if task_id_str else None

    async def clear_episode_task(self, episode_id: int) -> None:
        """
        Clear the episode-to-task mapping (e.g., when task completes or lock is stale)

        Args:
            episode_id: Episode ID to clear
        """
        key = TranscriptionStateKeys.EPISODE_TASK.format(episode_id=episode_id)
        await self.redis.cache_delete(key)
        logger.debug(f"Cleared episode {episode_id} task mapping")

    # === Progress Caching ===

    async def set_task_progress(
        self,
        task_id: int,
        status: str,
        progress: float,
        message: str,
        current_chunk: int = 0,
        total_chunks: int = 0,
        ttl_seconds: int = 3600
    ) -> None:
        """
        Cache task progress for fast polling

        Args:
            task_id: Task ID
            status: Current status enum value
            progress: Progress percentage (0-100)
            message: Status message
            current_chunk: Current chunk being processed
            total_chunks: Total number of chunks
            ttl_seconds: Cache TTL (default 1 hour)
        """
        key = TranscriptionStateKeys.TASK_PROGRESS.format(task_id=task_id)

        progress_data = {
            "task_id": task_id,
            "status": status,
            "progress": progress,
            "message": message,
            "current_chunk": current_chunk,
            "total_chunks": total_chunks,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

        await self.redis.cache_set(key, json.dumps(progress_data), ttl=ttl_seconds)

        # Also update lightweight status
        await self.set_task_status(task_id, status, progress, ttl_seconds)

        # Use throttle to reduce log frequency (log every 5% or every 5 seconds, whichever is longer)
        if _progress_throttle.should_log(task_id, status, progress):
            logger.info(f"📊 [PROGRESS] Task {task_id}: {progress:.1f}% - {message}")

    async def get_task_progress(self, task_id: int) -> dict[str, Any] | None:
        """
        Get cached task progress

        Args:
            task_id: Task ID

        Returns:
            Progress data dict or None if not found
        """
        key = TranscriptionStateKeys.TASK_PROGRESS.format(task_id=task_id)
        data = await self.redis.cache_get(key)

        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                logger.warning(f"Invalid cached progress data for task {task_id}")
        return None

    async def clear_task_progress(self, task_id: int) -> None:
        """
        Clear cached task progress

        Args:
            task_id: Task ID to clear
        """
        # Clear progress data
        progress_key = TranscriptionStateKeys.TASK_PROGRESS.format(task_id=task_id)
        await self.redis.cache_delete(progress_key)

        # Clear status data
        status_key = TranscriptionStateKeys.TASK_STATUS.format(task_id=task_id)
        await self.redis.cache_delete(status_key)

        logger.debug(f"Cleared progress cache for task {task_id}")

    # === Status Summary ===

    async def set_task_status(
        self,
        task_id: int,
        status: str,
        progress: float,
        ttl_seconds: int = 900
    ) -> None:
        """
        Set lightweight task status for dashboard queries

        Args:
            task_id: Task ID
            status: Current status
            progress: Progress percentage
            ttl_seconds: Cache TTL (default 15 minutes)
        """
        key = TranscriptionStateKeys.TASK_STATUS.format(task_id=task_id)

        status_data = {
            "status": status,
            "progress": progress,
            "updated_at": datetime.now(timezone.utc).isoformat()
        }

        await self.redis.cache_set(key, json.dumps(status_data), ttl=ttl_seconds)

    async def get_task_status(self, task_id: int) -> dict[str, Any] | None:
        """
        Get lightweight task status

        Args:
            task_id: Task ID

        Returns:
            Status data dict or None if not found
        """
        key = TranscriptionStateKeys.TASK_STATUS.format(task_id=task_id)
        data = await self.redis.cache_get(key)

        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                logger.warning(f"Invalid cached status data for task {task_id}")
        return None

    # === Cleanup ===

    async def clear_task_state(self, task_id: int, episode_id: int) -> None:
        """
        Clear all Redis state for a completed task

        Args:
            task_id: Task ID
            episode_id: Episode ID
        """
        try:
            # Release lock
            await self.release_task_lock(episode_id, task_id)

            # Clear episode mapping
            episode_key = TranscriptionStateKeys.EPISODE_TASK.format(episode_id=episode_id)
            client = await self.redis._get_client()
            await client.delete(episode_key)

            # Clear progress and status (they will expire naturally, but clear immediately)
            progress_key = TranscriptionStateKeys.TASK_PROGRESS.format(task_id=task_id)
            status_key = TranscriptionStateKeys.TASK_STATUS.format(task_id=task_id)
            await client.delete(progress_key, status_key)

            # Clear dispatched flag to allow re-processing if needed
            dispatched_key = f"podcast:transcription:dispatched:{task_id}"
            await client.delete(dispatched_key)

            logger.info(f"🧹 [STATE] Cleared Redis state for task {task_id}, episode {episode_id}")

        except Exception as e:
            logger.error(f"Failed to clear state for task {task_id}: {e}")

    async def fail_task_state(
        self,
        task_id: int,
        episode_id: int,
        error_message: str
    ) -> None:
        """
        Mark task as failed and clear locks

        Args:
            task_id: Task ID
            episode_id: Episode ID
            error_message: Error message
        """
        # Update progress to failed state (short TTL)
        await self.set_task_progress(
            task_id,
            TranscriptionStatus.FAILED.value,
            0,
            error_message,
            ttl_seconds=300  # 5 minutes
        )

        # Clear locks immediately
        await self.release_task_lock(episode_id, task_id)

        # Clear dispatched flag to allow re-processing if needed
        client = await self.redis._get_client()
        dispatched_key = f"podcast:transcription:dispatched:{task_id}"
        await client.delete(dispatched_key)
        logger.debug(f"Cleared dispatched flag for failed task {task_id}")

        logger.error(f"❌ [STATE] Task {task_id} failed: {error_message}")

    # === Batch Operations ===

    async def get_active_tasks_count(self) -> int:
        """
        Get count of tasks currently in progress (from Redis)

        Returns:
            Number of active tasks
        """
        try:
            client = await self.redis._get_client()
            # Count task progress keys (they exist only for active tasks)
            keys = await client.keys("podcast:transcription:progress:*")
            return len(keys)
        except Exception as e:
            logger.error(f"Failed to get active tasks count: {e}")
            return 0

    async def cleanup_stale_locks(self, max_age_seconds: int = 7200) -> int:
        """
        Cleanup stale locks older than max_age_seconds (2 hours default)

        Args:
            max_age_seconds: Maximum age of locks to keep

        Returns:
            Number of locks cleaned up
        """
        try:
            client = await self.redis._get_client()
            lock_keys = await client.keys("podcast:transcription:lock_value:*")

            cleaned = 0
            now = datetime.now(timezone.utc)

            for key in lock_keys:
                ttl = await client.ttl(key)
                if ttl == -1:  # No expiration set - stale lock
                    await client.delete(key)
                    cleaned += 1
                elif ttl > max_age_seconds:
                    # Lock has too long expiration, reset it
                    await client.delete(key)
                    cleaned += 1

            if cleaned > 0:
                logger.info(f"🧹 [STATE] Cleaned up {cleaned} stale locks")

            return cleaned

        except Exception as e:
            logger.error(f"Failed to cleanup stale locks: {e}")
            return 0


# Singleton instance
_state_manager = None


async def get_transcription_state_manager() -> TranscriptionStateManager:
    """Get singleton state manager instance"""
    global _state_manager
    if _state_manager is None:
        _state_manager = TranscriptionStateManager()
    return _state_manager
