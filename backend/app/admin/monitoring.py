"""
System monitoring service module.
系统监控服务模块。

Provides host system resource monitoring capabilities inspired by Prometheus node_exporter.
提供参考 Prometheus node_exporter 的宿主机系统资源监控功能。
"""
import logging
import os
import platform
from datetime import datetime, timezone
from typing import Dict, List, Optional

import psutil
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# =============================================================================
# Data Models / 数据模型
# =============================================================================


class SystemInfo(BaseModel):
    """System basic information / 系统基础信息"""

    hostname: str = Field(..., description="Hostname / 主机名")
    os_type: str = Field(..., description="Operating System type / 操作系统类型")
    os_release: str = Field(..., description="OS release / 操作系统版本")
    os_version: str = Field(..., description="OS version / 操作系统详细版本")
    architecture: str = Field(..., description="System architecture / 系统架构")
    boot_time: float = Field(..., description="Boot time timestamp / 启动时间戳")
    uptime_seconds: float = Field(..., description="Uptime in seconds / 运行时间（秒）")
    current_users: int = Field(..., description="Number of current users / 当前用户数")
    cpu_count: int = Field(..., description="Number of CPU cores / CPU 核心数")


class CPUMetrics(BaseModel):
    """CPU metrics / CPU 指标"""

    usage_percent: float = Field(..., description="Overall CPU usage % / CPU 总体使用率")
    per_cpu_percent: List[float] = Field(..., description="Per-core CPU usage % / 各核心使用率")
    user_time: float = Field(..., description="User CPU time (seconds) / 用户态时间")
    system_time: float = Field(..., description="System CPU time (seconds) / 系统态时间")
    idle_time: float = Field(..., description="Idle CPU time (seconds) / 空闲时间")
    iowait_time: float = Field(default=0, description="IO wait time (seconds) / IO等待时间")
    context_switches: int = Field(..., description="Context switches count / 上下文切换次数")
    interrupts: int = Field(..., description="Interrupts count / 中断次数")
    load_average_1min: float = Field(..., description="1 min load average / 1分钟负载")
    load_average_5min: float = Field(..., description="5 min load average / 5分钟负载")
    load_average_15min: float = Field(..., description="15 min load average / 15分钟负载")


class MemoryMetrics(BaseModel):
    """Memory metrics / 内存指标"""

    total_gb: float = Field(..., description="Total memory in GB / 内存总量(GB)")
    used_gb: float = Field(..., description="Used memory in GB / 已用内存(GB)")
    available_gb: float = Field(..., description="Available memory in GB / 可用内存(GB)")
    percent: float = Field(..., description="Memory usage % / 内存使用率")
    buffered_gb: float = Field(default=0, description="Buffered memory in GB / 缓冲内存(GB)")
    cached_gb: float = Field(default=0, description="Cached memory in GB / 缓存内存(GB)")
    swap_total_gb: float = Field(..., description="Total swap in GB / 交换分区总量(GB)")
    swap_used_gb: float = Field(..., description="Used swap in GB / 已用交换分区(GB)")
    swap_percent: float = Field(..., description="Swap usage % / 交换分区使用率")


class DiskPartition(BaseModel):
    """Disk partition info / 磁盘分区信息"""

    device: str = Field(..., description="Device path / 设备路径")
    mountpoint: str = Field(..., description="Mount point / 挂载点")
    fstype: str = Field(..., description="Filesystem type / 文件系统类型")
    total_gb: float = Field(..., description="Total capacity in GB / 总容量(GB)")
    used_gb: float = Field(..., description="Used capacity in GB / 已用容量(GB)")
    free_gb: float = Field(..., description="Free capacity in GB / 可用容量(GB)")
    percent: float = Field(..., description="Usage percentage / 使用率")


class DiskMetrics(BaseModel):
    """Disk metrics / 磁盘指标"""

    partitions: List[DiskPartition] = Field(default_factory=list, description="Disk partitions / 磁盘分区列表")
    read_bytes: int = Field(..., description="Total bytes read / 读取字节数")
    write_bytes: int = Field(..., description="Total bytes written / 写入字节数")
    read_count: int = Field(..., description="Number of read operations / 读取操作次数")
    write_count: int = Field(..., description="Number of write operations / 写入操作次数")
    read_time_ms: int = Field(..., description="Total read time in ms / 读时间(毫秒)")
    write_time_ms: int = Field(..., description="Total write time in ms / 写时间(毫秒)")


class NetworkInterface(BaseModel):
    """Network interface info / 网络接口信息"""

    name: str = Field(..., description="Interface name / 接口名称")
    is_up: bool = Field(..., description="Is interface up / 是否活动")
    bytes_sent: int = Field(..., description="Bytes sent / 发送字节数")
    bytes_recv: int = Field(..., description="Bytes received / 接收字节数")
    packets_sent: int = Field(..., description="Packets sent / 发送包数")
    packets_recv: int = Field(..., description="Packets received / 接收包数")
    errors_in: int = Field(default=0, description="Incoming errors / 接收错误数")
    errors_out: int = Field(default=0, description="Outgoing errors / 发送错误数")
    drop_in: int = Field(default=0, description="Incoming dropped / 接收丢弃数")
    drop_out: int = Field(default=0, description="Outgoing dropped / 发送丢弃数")


class NetworkMetrics(BaseModel):
    """Network metrics / 网络指标"""

    interfaces: List[NetworkInterface] = Field(default_factory=list, description="Network interfaces / 网络接口列表")
    total_bytes_sent: int = Field(..., description="Total bytes sent / 总发送字节数")
    total_bytes_recv: int = Field(..., description="Total bytes received / 总接收字节数")


class SystemMetrics(BaseModel):
    """Complete system metrics / 完整的系统指标"""

    system_info: SystemInfo = Field(..., description="System information / 系统信息")
    cpu: CPUMetrics = Field(..., description="CPU metrics / CPU 指标")
    memory: MemoryMetrics = Field(..., description="Memory metrics / 内存指标")
    disk: DiskMetrics = Field(..., description="Disk metrics / 磁盘指标")
    network: NetworkMetrics = Field(..., description="Network metrics / 网络指标")
    timestamp: float = Field(..., description="Collection timestamp / 采集时间戳")


# =============================================================================
# Monitoring Service / 监控服务
# =============================================================================


class SystemMonitorService:
    """
    System monitoring service.
    系统监控服务。

    Collects various system metrics using psutil library.
    使用 psutil 库采集各种系统指标。
    """

    def __init__(self):
        """Initialize the monitoring service / 初始化监控服务"""
        self._boot_time: Optional[float] = None

    def get_system_info(self) -> SystemInfo:
        """
        Get system basic information.
        获取系统基础信息。

        Returns:
            SystemInfo: System basic information / 系统基础信息
        """
        try:
            # Get boot time (cached for consistency)
            if self._boot_time is None:
                self._boot_time = psutil.boot_time()

            # Calculate uptime
            uptime = datetime.now(timezone.utc).timestamp() - self._boot_time

            # Get system info
            uname = platform.uname()
            hostname = uname.node or os.getenv("HOSTNAME", "unknown")

            # Get current users
            users = psutil.users()

            return SystemInfo(
                hostname=hostname,
                os_type=uname.system,
                os_release=uname.release,
                os_version=uname.version,
                architecture=uname.machine,
                boot_time=self._boot_time,
                uptime_seconds=uptime,
                current_users=len(users),
                cpu_count=psutil.cpu_count(logical=True),
            )
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            raise

    def get_cpu_metrics(self) -> CPUMetrics:
        """
        Get CPU metrics.
        获取 CPU 指标。

        Returns:
            CPUMetrics: CPU metrics / CPU 指标
        """
        try:
            # Overall CPU usage
            cpu_percent = psutil.cpu_percent(interval=0.1)

            # Per-core CPU usage
            per_cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)

            # CPU times
            cpu_times = psutil.cpu_times()
            user_time = cpu_times.user
            system_time = cpu_times.system
            idle_time = cpu_times.idle
            iowait_time = getattr(cpu_times, "iowait", 0.0)

            # CPU stats
            cpu_stats = psutil.cpu_stats()
            context_switches = cpu_stats.ctx_switches
            interrupts = cpu_stats.interrupts

            # Load average (Unix only)
            load_avg = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

            return CPUMetrics(
                usage_percent=cpu_percent,
                per_cpu_percent=per_cpu_percent,
                user_time=user_time,
                system_time=system_time,
                idle_time=idle_time,
                iowait_time=iowait_time,
                context_switches=context_switches,
                interrupts=interrupts,
                load_average_1min=load_avg[0],
                load_average_5min=load_avg[1],
                load_average_15min=load_avg[2],
            )
        except Exception as e:
            logger.error(f"Error getting CPU metrics: {e}")
            raise

    def get_memory_metrics(self) -> MemoryMetrics:
        """
        Get memory metrics.
        获取内存指标。

        Returns:
            MemoryMetrics: Memory metrics / 内存指标
        """
        try:
            # Virtual memory
            vmem = psutil.virtual_memory()

            # Swap memory
            swap = psutil.swap_memory()

            return MemoryMetrics(
                total_gb=vmem.total / (1024**3),
                used_gb=vmem.used / (1024**3),
                available_gb=vmem.available / (1024**3),
                percent=vmem.percent,
                buffered_gb=getattr(vmem, "buffers", 0) / (1024**3),
                cached_gb=getattr(vmem, "cached", 0) / (1024**3),
                swap_total_gb=swap.total / (1024**3),
                swap_used_gb=swap.used / (1024**3),
                swap_percent=swap.percent,
            )
        except Exception as e:
            logger.error(f"Error getting memory metrics: {e}")
            raise

    def get_disk_metrics(self) -> DiskMetrics:
        """
        Get disk metrics.
        获取磁盘指标。

        Returns:
            DiskMetrics: Disk metrics / 磁盘指标
        """
        try:
            # Get disk partitions
            partitions = []
            for part in psutil.disk_partitions(all=True):
                try:
                    # Skip some filesystems that might cause issues
                    if part.fstype in ["squashfs", "tmpfs", "proc", "sysfs", "devtmpfs"]:
                        continue

                    usage = psutil.disk_usage(part.mountpoint)
                    partitions.append(
                        DiskPartition(
                            device=part.device,
                            mountpoint=part.mountpoint,
                            fstype=part.fstype,
                            total_gb=usage.total / (1024**3),
                            used_gb=usage.used / (1024**3),
                            free_gb=usage.free / (1024**3),
                            percent=usage.percent,
                        )
                    )
                except (PermissionError, OSError):
                    # Skip partitions that can't be accessed
                    logger.debug(f"Skipping inaccessible partition: {part.mountpoint}")
                    continue

            # Get disk I/O stats
            io_counters = psutil.disk_io_counters()
            if io_counters:
                read_bytes = io_counters.read_bytes
                write_bytes = io_counters.write_bytes
                read_count = io_counters.read_count
                write_count = io_counters.write_count
                read_time_ms = getattr(io_counters, "read_time", 0)
                write_time_ms = getattr(io_counters, "write_time", 0)
            else:
                # Default values if not available
                read_bytes = write_bytes = read_count = write_count = read_time_ms = write_time_ms = 0

            return DiskMetrics(
                partitions=partitions,
                read_bytes=read_bytes,
                write_bytes=write_bytes,
                read_count=read_count,
                write_count=write_count,
                read_time_ms=read_time_ms,
                write_time_ms=write_time_ms,
            )
        except Exception as e:
            logger.error(f"Error getting disk metrics: {e}")
            raise

    def get_network_metrics(self) -> NetworkMetrics:
        """
        Get network metrics.
        获取网络指标。

        Returns:
            NetworkMetrics: Network metrics / 网络指标
        """
        try:
            # Get network I/O counters per interface
            net_io = psutil.net_io_counters(pernic=True)

            # Get interface addresses to determine which are up
            addrs = psutil.net_if_addrs()

            interfaces = []
            total_sent = 0
            total_recv = 0

            for iface_name, io_counter in net_io.items():
                # Check if interface is up (has an IP address)
                is_up = iface_name in addrs and any(
                    addr.family == 2  # AF_INET
                    for addr in addrs[iface_name]
                )

                interface = NetworkInterface(
                    name=iface_name,
                    is_up=is_up,
                    bytes_sent=io_counter.bytes_sent,
                    bytes_recv=io_counter.bytes_recv,
                    packets_sent=io_counter.packets_sent,
                    packets_recv=io_counter.packets_recv,
                    errors_in=io_counter.errin,
                    errors_out=io_counter.errout,
                    drop_in=io_counter.dropin,
                    drop_out=io_counter.dropout,
                )
                interfaces.append(interface)

                total_sent += io_counter.bytes_sent
                total_recv += io_counter.bytes_recv

            # Sort interfaces: active ones first, then by name
            interfaces.sort(key=lambda x: (not x.is_up, x.name))

            return NetworkMetrics(
                interfaces=interfaces,
                total_bytes_sent=total_sent,
                total_bytes_recv=total_recv,
            )
        except Exception as e:
            logger.error(f"Error getting network metrics: {e}")
            raise

    def get_all_metrics(self) -> SystemMetrics:
        """
        Get all system metrics.
        获取所有系统指标。

        Returns:
            SystemMetrics: Complete system metrics / 完整的系统指标
        """
        try:
            timestamp = datetime.now(timezone.utc).timestamp()

            return SystemMetrics(
                system_info=self.get_system_info(),
                cpu=self.get_cpu_metrics(),
                memory=self.get_memory_metrics(),
                disk=self.get_disk_metrics(),
                network=self.get_network_metrics(),
                timestamp=timestamp,
            )
        except Exception as e:
            logger.error(f"Error getting all metrics: {e}")
            raise


# Singleton instance
_monitor_service: Optional[SystemMonitorService] = None


def get_monitor_service() -> SystemMonitorService:
    """
    Get the singleton monitor service instance.
    获取监控服务单例。

    Returns:
        SystemMonitorService: Monitor service instance / 监控服务实例
    """
    global _monitor_service
    if _monitor_service is None:
        _monitor_service = SystemMonitorService()
    return _monitor_service
