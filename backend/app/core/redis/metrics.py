"""Redis Metrics Recording.

Handles command timing, cache hit/miss tracking, and penetration metrics.
"""

import logging
from time import perf_counter
from typing import Any

logger = logging.getLogger(__name__)

# Redis keys for distributed runtime metrics
_METRICS_COMMANDS_KEY = "podcast:metrics:commands"
_METRICS_CACHE_KEY = "podcast:metrics:cache"
_METRICS_CACHE_PENETRATION_KEY = "podcast:metrics:penetration"


class MetricsOperations:
    """Records and retrieves Redis runtime metrics."""

    @staticmethod
    def _cache_namespace(key: str) -> str:
        """Extract namespace from cache key for metrics grouping."""
        parts = key.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3])
        if len(parts) >= 2:
            return ":".join(parts[:2])
        return parts[0] if parts else "unknown"

    async def _record_command_timing(
        self, command: str, elapsed_ms: float, client: Any = None
    ) -> None:
        """Record command timing in Redis using atomic operations."""
        from app.core.cache_ttl import CacheTTL

        # Get client if not provided (for backward compatibility)
        if client is None:
            client = await self._get_client()

        try:
            # Use pipeline for atomic multi-operation
            async with client.pipeline() as pipe:
                # Total count and time
                pipe.hincrby(_METRICS_COMMANDS_KEY, "total_count", 1)
                pipe.hincrbyfloat(_METRICS_COMMANDS_KEY, "total_ms", elapsed_ms)

                # Track max_ms using Lua script for atomic max update
                max_update_script = """
                    local current = redis.call('HGET', KEYS[1], 'max_ms')
                    local new_val = tonumber(ARGV[1])
                    if current then
                        current = tonumber(current)
                        if new_val > current then
                            redis.call('HSET', KEYS[1], 'max_ms', new_val)
                        end
                    else
                        redis.call('HSET', KEYS[1], 'max_ms', new_val)
                    end
                """
                pipe.eval(max_update_script, 1, _METRICS_COMMANDS_KEY, elapsed_ms)

                # Per-command stats
                pipe.hincrby(f"{_METRICS_COMMANDS_KEY}:by_command:{command}", "count", 1)
                pipe.hincrbyfloat(
                    f"{_METRICS_COMMANDS_KEY}:by_command:{command}", "total_ms", elapsed_ms
                )

                # Update max_ms for specific command
                pipe.eval(
                    max_update_script, 1,
                    f"{_METRICS_COMMANDS_KEY}:by_command:{command}", elapsed_ms
                )

                # Set TTL on all keys
                pipe.expire(_METRICS_COMMANDS_KEY, CacheTTL.METRICS)
                pipe.expire(
                    f"{_METRICS_COMMANDS_KEY}:by_command:{command}", CacheTTL.METRICS
                )

                await pipe.execute()
        except Exception:
            # Silently fail to avoid impacting main operations
            pass

    async def _record_cache_lookup(self, key: str, *, hit: bool, client: Any = None) -> None:
        """Record cache lookup in Redis using atomic operations."""
        from app.core.cache_ttl import CacheTTL

        # Get client if not provided (for backward compatibility)
        if client is None:
            client = await self._get_client()

        try:
            namespace = self._cache_namespace(key)
            field = "hits" if hit else "misses"

            async with client.pipeline() as pipe:
                # Global stats
                pipe.hincrby(_METRICS_CACHE_KEY, field, 1)

                # Per-namespace stats
                pipe.hincrby(f"{_METRICS_CACHE_KEY}:namespace:{namespace}", field, 1)

                # Set TTL
                pipe.expire(_METRICS_CACHE_KEY, CacheTTL.METRICS)
                pipe.expire(
                    f"{_METRICS_CACHE_KEY}:namespace:{namespace}", CacheTTL.METRICS
                )

                await pipe.execute()
        except Exception:
            # Silently fail to avoid impacting main operations
            pass

    async def _record_cache_penetration(self, key: str, client: Any = None) -> None:
        """Record cache penetration event (query for non-existent data)."""
        from app.core.cache_ttl import CacheTTL

        # Get client if not provided (for backward compatibility)
        if client is None:
            client = await self._get_client()

        try:
            namespace = self._cache_namespace(key)

            async with client.pipeline() as pipe:
                # Global penetration counter
                pipe.hincrby(_METRICS_CACHE_PENETRATION_KEY, "total_attempts", 1)

                # Per-namespace penetration counter
                pipe.hincrby(
                    f"{_METRICS_CACHE_PENETRATION_KEY}:namespace:{namespace}",
                    "attempts",
                    1,
                )

                # Set TTL
                pipe.expire(_METRICS_CACHE_PENETRATION_KEY, CacheTTL.METRICS)
                pipe.expire(
                    f"{_METRICS_CACHE_PENETRATION_KEY}:namespace:{namespace}",
                    CacheTTL.METRICS,
                )

                await pipe.execute()
        except Exception:
            # Silently fail to avoid impacting main operations
            pass

    async def get_runtime_metrics(self, client: Any) -> dict[str, Any]:
        """Get runtime metrics from Redis (aggregated across all processes)."""
        started = perf_counter()

        try:
            # Get command metrics
            commands_data = await client.hgetall(_METRICS_COMMANDS_KEY) or {}
            total_count = int(commands_data.get("total_count", 0))
            total_ms = float(commands_data.get("total_ms", 0.0))
            max_ms = float(commands_data.get("max_ms", 0.0))
            avg_ms = (total_ms / total_count) if total_count else 0.0

            # Get per-command metrics
            by_command: dict[str, Any] = {}
            command_keys_pattern = f"{_METRICS_COMMANDS_KEY}:by_command:*"
            async for key in client.scan_iter(match=command_keys_pattern):
                command_name = key.split(":")[-1]
                cmd_data = await client.hgetall(key) or {}
                count = int(cmd_data.get("count", 0))
                cmd_total_ms = float(cmd_data.get("total_ms", 0.0))
                cmd_max_ms = float(cmd_data.get("max_ms", 0.0))
                by_command[command_name] = {
                    "count": count,
                    "avg_ms": (cmd_total_ms / count) if count else 0.0,
                    "max_ms": cmd_max_ms,
                }

            # Get cache metrics
            cache_data = await client.hgetall(_METRICS_CACHE_KEY) or {}
            hits = int(cache_data.get("hits", 0))
            misses = int(cache_data.get("misses", 0))
            lookups = hits + misses
            hit_rate = (hits / lookups) if lookups else 0.0

            # Get per-namespace metrics
            by_namespace: dict[str, Any] = {}
            namespace_pattern = f"{_METRICS_CACHE_KEY}:namespace:*"
            async for key in client.scan_iter(match=namespace_pattern):
                namespace = key.split(":")[-1]
                ns_data = await client.hgetall(key) or {}
                ns_hits = int(ns_data.get("hits", 0))
                ns_misses = int(ns_data.get("misses", 0))
                ns_total = ns_hits + ns_misses
                by_namespace[namespace] = {
                    "hits": ns_hits,
                    "misses": ns_misses,
                    "hit_rate": (ns_hits / ns_total) if ns_total else 0.0,
                }

            await self._record_command_timing(
                client, "HGETALL", (perf_counter() - started) * 1000
            )

            # Get cache penetration metrics
            penetration_data = await client.hgetall(_METRICS_CACHE_PENETRATION_KEY) or {}
            total_penetration = int(penetration_data.get("total_attempts", 0))

            # Get per-namespace penetration metrics
            penetration_by_namespace: dict[str, Any] = {}
            penetration_pattern = f"{_METRICS_CACHE_PENETRATION_KEY}:namespace:*"
            async for key in client.scan_iter(match=penetration_pattern):
                namespace = key.split(":")[-1]
                ns_data = await client.hgetall(key) or {}
                ns_attempts = int(ns_data.get("attempts", 0))
                penetration_by_namespace[namespace] = {
                    "attempts": ns_attempts,
                }

            return {
                "commands": {
                    "total_count": total_count,
                    "avg_ms": avg_ms,
                    "max_ms": max_ms,
                    "by_command": by_command,
                },
                "cache": {
                    "hits": hits,
                    "misses": misses,
                    "hit_rate": hit_rate,
                    "by_namespace": by_namespace,
                },
                "penetration": {
                    "total_attempts": total_penetration,
                    "by_namespace": penetration_by_namespace,
                },
            }
        except Exception:
            # Return empty metrics on error
            return {
                "commands": {
                    "total_count": 0,
                    "avg_ms": 0.0,
                    "max_ms": 0.0,
                    "by_command": {},
                },
                "cache": {
                    "hits": 0,
                    "misses": 0,
                    "hit_rate": 0.0,
                    "by_namespace": {},
                },
                "penetration": {
                    "total_attempts": 0,
                    "by_namespace": {},
                },
            }

    async def get_penetration_metrics(self, client: Any) -> dict[str, Any]:
        """Get cache penetration metrics."""
        try:
            penetration_data = await client.hgetall(_METRICS_CACHE_PENETRATION_KEY) or {}
            total_attempts = int(penetration_data.get("total_attempts", 0))

            # Get per-namespace penetration metrics
            by_namespace: dict[str, Any] = {}
            penetration_pattern = f"{_METRICS_CACHE_PENETRATION_KEY}:namespace:*"
            async for key in client.scan_iter(match=penetration_pattern):
                namespace = key.split(":")[-1]
                ns_data = await client.hgetall(key) or {}
                ns_attempts = int(ns_data.get("attempts", 0))
                by_namespace[namespace] = {
                    "attempts": ns_attempts,
                }

            return {
                "total_attempts": total_attempts,
                "by_namespace": by_namespace,
            }
        except Exception:
            return {
                "total_attempts": 0,
                "by_namespace": {},
            }


# Backward compatibility alias
RedisMetrics = MetricsOperations
