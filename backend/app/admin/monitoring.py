"""System monitoring service for admin panel."""

from __future__ import annotations

import os
import platform
from datetime import UTC, datetime
from typing import Any

import psutil


def _safe_load_average() -> tuple[float, float, float]:
    try:
        return os.getloadavg()
    except (AttributeError, OSError):
        return (0.0, 0.0, 0.0)


class SystemMonitorService:
    """Collect host resource metrics for the admin dashboard."""

    def get_system_info(self) -> dict[str, Any]:
        uname = platform.uname()
        boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
        uptime_seconds = max(
            0.0, (datetime.now(UTC) - boot_time).total_seconds()
        )
        return {
            "hostname": uname.node,
            "os_type": uname.system,
            "os_version": uname.release,
            "architecture": uname.machine,
            "boot_time": boot_time.isoformat(),
            "uptime_seconds": uptime_seconds,
            "current_users": len(psutil.users()),
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def get_cpu_metrics(self) -> dict[str, Any]:
        cpu_times = psutil.cpu_times()
        cpu_stats = psutil.cpu_stats()
        load_1m, load_5m, load_15m = _safe_load_average()
        return {
            "usage_percent": psutil.cpu_percent(interval=0.1),
            "per_cpu_percent": psutil.cpu_percent(interval=0.1, percpu=True),
            "user_time": getattr(cpu_times, "user", 0.0),
            "system_time": getattr(cpu_times, "system", 0.0),
            "idle_time": getattr(cpu_times, "idle", 0.0),
            "context_switches": getattr(cpu_stats, "ctx_switches", 0),
            "interrupts": getattr(cpu_stats, "interrupts", 0),
            "load_average_1min": load_1m,
            "load_average_5min": load_5m,
            "load_average_15min": load_15m,
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def get_memory_metrics(self) -> dict[str, Any]:
        virtual_memory = psutil.virtual_memory()
        swap = psutil.swap_memory()
        return {
            "total_bytes": virtual_memory.total,
            "used_bytes": virtual_memory.used,
            "available_bytes": virtual_memory.available,
            "percent": virtual_memory.percent,
            "buffered_bytes": getattr(virtual_memory, "buffers", 0),
            "cached_bytes": getattr(virtual_memory, "cached", 0),
            "swap_total_bytes": swap.total,
            "swap_used_bytes": swap.used,
            "swap_percent": swap.percent,
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def get_disk_metrics(self) -> dict[str, Any]:
        partitions: list[dict[str, Any]] = []
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
            except (PermissionError, FileNotFoundError, OSError):
                continue

            partitions.append(
                {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent": usage.percent,
                }
            )

        io_counters = psutil.disk_io_counters()
        return {
            "partitions": partitions,
            "read_bytes": getattr(io_counters, "read_bytes", 0),
            "write_bytes": getattr(io_counters, "write_bytes", 0),
            "read_count": getattr(io_counters, "read_count", 0),
            "write_count": getattr(io_counters, "write_count", 0),
            "io_time_ms": getattr(io_counters, "read_time", 0)
            + getattr(io_counters, "write_time", 0),
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def get_network_metrics(self) -> dict[str, Any]:
        by_interface: list[dict[str, Any]] = []
        net_io = psutil.net_io_counters(pernic=True)
        interface_stats = psutil.net_if_stats()
        for name, counters in net_io.items():
            state = interface_stats.get(name)
            by_interface.append(
                {
                    "name": name,
                    "is_up": bool(getattr(state, "isup", False)),
                    "speed_mbps": getattr(state, "speed", 0),
                    "bytes_sent": getattr(counters, "bytes_sent", 0),
                    "bytes_recv": getattr(counters, "bytes_recv", 0),
                    "packets_sent": getattr(counters, "packets_sent", 0),
                    "packets_recv": getattr(counters, "packets_recv", 0),
                    "errin": getattr(counters, "errin", 0),
                    "errout": getattr(counters, "errout", 0),
                    "dropin": getattr(counters, "dropin", 0),
                    "dropout": getattr(counters, "dropout", 0),
                }
            )

        return {
            "interfaces": by_interface,
            "updated_at": datetime.now(UTC).isoformat(),
        }

    def get_all_metrics(self) -> dict[str, Any]:
        return {
            "system_info": self.get_system_info(),
            "cpu": self.get_cpu_metrics(),
            "memory": self.get_memory_metrics(),
            "disk": self.get_disk_metrics(),
            "network": self.get_network_metrics(),
            "updated_at": datetime.now(UTC).isoformat(),
        }

