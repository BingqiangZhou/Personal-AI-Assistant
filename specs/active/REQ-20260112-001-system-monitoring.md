# 系统监控增强 - 宿主机资源监控 / System Monitoring Enhancement - Host Resource Monitoring

## 基本信息 / Basic Information
- **需求ID**: REQ-20260112-001
- **创建日期**: 2026-01-12
- **最后更新**: 2026-01-12
- **负责人**: Product Manager
- **状态**: Active
- **优先级**: Medium

## 需求描述 / Requirements Description

### 用户故事 / User Story
**中文**: 作为系统管理员，我想要在管理面板中查看详细的宿主机系统资源监控信息（参考 Prometheus node_exporter），以便能够实时了解系统运行状态、及时发现性能瓶颈和潜在问题。

**English**: As a system administrator, I want to view detailed host system resource monitoring information in the admin panel (inspired by Prometheus node_exporter), so that I can understand system runtime status in real-time and identify performance bottlenecks and potential issues.

### 业务价值 / Business Value
- **提高运维效率**: 通过可视化界面快速了解系统健康状况 / **Improved Operations Efficiency**: Quickly understand system health through visual interface
- **预防性维护**: 提前发现资源使用异常，避免系统故障 / **Preventive Maintenance**: Detect resource usage anomalies early to avoid system failures
- **成本优化**: 了解资源使用情况，优化资源配置 / **Cost Optimization**: Understand resource usage to optimize resource allocation
- **成功指标** / **Success Metrics**:
  - 管理员可以在30秒内掌握系统整体健康状况 / Admin can grasp overall system health within 30 seconds
  - 监控数据刷新延迟 < 3秒 / Monitoring data refresh latency < 3 seconds
  - 能够识别常见性能问题（内存泄漏、磁盘空间不足等）/ Able to identify common performance issues (memory leaks, disk space shortage, etc.)

### 背景信息 / Background Information
- **当前状况**: 管理面板已有基础监控页面，仅显示 CPU、内存、磁盘使用率 / **Current State**: Admin panel has basic monitoring page showing only CPU, memory, and disk usage
- **用户痛点** / **User Pain Points**:
  - 缺乏详细的系统资源指标（CPU各核使用率、网络流量、磁盘IO等）/ Lacks detailed system resource metrics (per-core CPU usage, network traffic, disk I/O, etc.)
  - 无法查看系统运行时间和负载信息 / Cannot view system uptime and load information
  - 缺少历史趋势数据对比 / Lacks historical trend data comparison
  - 无法查看进程和服务状态 / Cannot view process and service status
- **机会点** / **Opportunities**:
  - 参考 Prometheus node_exporter 的指标体系 / Reference Prometheus node_exporter metrics system
  - 使用 psutil 库获取系统信息 / Use psutil library to get system information
  - 提供实时数据更新功能 / Provide real-time data update capability

## 功能需求 / Functional Requirements

### 核心功能 / Core Functions
- [FR-001] 系统基础信息展示
- [FR-002] CPU 详细指标监控
- [FR-003] 内存详细指标监控
- [FR-004] 磁盘和文件系统监控
- [FR-005] 网络接口监控
- [FR-006] 实时数据刷新

### 功能详述 / Function Details

#### 功能1：系统基础信息展示 / System Basic Information
- **描述**: 显示系统基本信息，帮助管理员快速了解系统环境 / **Description**: Display basic system information to help admins understand system environment
- **指标** / **Metrics**:
  - 主机名 / Hostname
  - 操作系统类型和版本 / OS Type and Version
  - 系统架构 (x86_64, ARM等) / System Architecture
  - 系统启动时间 / System Boot Time
  - 系统运行时间 / System Uptime
  - 当前用户数 / Current User Count
- **实现方式** / **Implementation**:
  - 使用 `psutil.boot_time()` 获取启动时间 / Use `psutil.boot_time()` for boot time
  - 使用 `platform.uname()` 获取系统信息 / Use `platform.uname()` for system info
  - 使用 `psutil.users()` 获取当前用户 / Use `psutil.users()` for current users

#### 功能2：CPU 详细指标监控 / CPU Detailed Metrics
- **描述**: 监控 CPU 的详细使用情况 / **Description**: Monitor detailed CPU usage
- **指标** / **Metrics**:
  - CPU 总体使用率 (%) / Overall CPU Usage (%)
  - 各 CPU 核心使用率 (%) / Per-CPU Core Usage (%)
  - CPU 时间分布（用户态、系统态、空闲） / CPU Time Distribution (user, system, idle)
  - CPU 上下文切换次数 / CPU Context Switches
  - CPU 中断次数 / CPU Interrupts
  - 系统 1/5/15 分钟平均负载 / System Load Average (1/5/15 min)
- **实现方式** / **Implementation**:
  - `psutil.cpu_percent()` - 总体使用率 / Overall usage
  - `psutil.cpu_percent(percpu=True)` - 各核心使用率 / Per-core usage
  - `psutil.cpu_times()` - CPU 时间 / CPU time
  - `psutil.cpu_stats()` - CPU 统计 / CPU stats
  - `os.getloadavg()` - 系统负载 / System load

#### 功能3：内存详细指标监控 / Memory Detailed Metrics
- **描述**: 监控内存和交换分区的详细使用情况 / **Description**: Monitor detailed memory and swap usage
- **指标** / **Metrics**:
  - 物理内存总量 / Total Physical Memory
  - 物理内存已用 / Used Physical Memory
  - 物理内存可用 / Available Physical Memory
  - 物理内存使用率 (%) / Physical Memory Usage (%)
  - 缓冲区内存 / Buffer Memory
  - 缓存内存 / Cached Memory
  - 交换分区总量 / Total Swap
  - 交换分区已用 / Used Swap
  - 交换分区使用率 (%) / Swap Usage (%)
- **实现方式** / **Implementation**:
  - `psutil.virtual_memory()` - 物理内存信息 / Physical memory info
  - `psutil.swap_memory()` - 交换分区信息 / Swap info

#### 功能4：磁盘和文件系统监控 / Disk and Filesystem Monitoring
- **描述**: 监控所有磁盘分区的使用情况和 IO 统计 / **Description**: Monitor all disk partitions usage and I/O stats
- **指标** / **Metrics**:
  - 所有磁盘分区列表 / All Disk Partitions List
  - 每个分区：
    - 挂载点 / Mount Point
    - 文件系统类型 / Filesystem Type
    - 总容量 / Total Capacity
    - 已用容量 / Used Capacity
    - 可用容量 / Available Capacity
    - 使用率 (%) / Usage (%)
  - 磁盘 IO 统计 / Disk I/O Stats:
    - 读字节数 / Bytes Read
    - 写字节数 / Bytes Written
    - 读操作次数 / Read Operations
    - 写操作次数 / Write Operations
    - IO 时间 / I/O Time
- **实现方式** / **Implementation**:
  - `psutil.disk_partitions()` - 磁盘分区列表 / Disk partitions
  - `psutil.disk_usage(path)` - 分区使用情况 / Partition usage
  - `psutil.disk_io_counters()` - IO 统计 / I/O stats

#### 功能5：网络接口监控 / Network Interface Monitoring
- **描述**: 监控所有网络接口的流量统计 / **Description**: Monitor all network interfaces traffic stats
- **指标** / **Metrics**:
  - 所有网络接口列表 / All Network Interfaces List
  - 每个接口：
    - 接口名称 / Interface Name
    - 是否活动 / Is Active
    - 发送字节数 / Bytes Sent
    - 接收字节数 / Bytes Received
    - 发送包数 / Packets Sent
    - 接收包数 / Packets Received
    - 错误包数 / Packet Errors
    - 丢弃包数 / Packets Dropped
- **实现方式** / **Implementation**:
  - `psutil.net_io_counters(pernic=True)` - 各网卡 IO 统计 / Per-NIC I/O stats
  - `psutil.net_if_addrs()` - 网卡地址 / NIC addresses
  - `psutil.net_connections()` - 网络连接（可选） / Network connections (optional)

#### 功能6：实时数据刷新 / Real-time Data Refresh
- **描述**: 支持手动刷新和自动刷新功能 / **Description**: Support manual and auto-refresh
- **功能** / **Features**:
  - 手动刷新按钮 / Manual Refresh Button
  - 自动刷新选项（可配置间隔：10秒、30秒、1分钟）/ Auto-refresh option (configurable interval: 10s, 30s, 1m)
  - 数据更新时间戳 / Data Update Timestamp
- **实现方式** / **Implementation**:
  - 使用 JavaScript `setInterval()` 实现自动刷新 / Use JavaScript `setInterval()` for auto-refresh
  - 使用 htmx 或 fetch API 进行无刷新更新 / Use htmx or fetch API for refresh-less updates

## 非功能需求 / Non-functional Requirements

### 性能要求 / Performance Requirements
- **数据采集时间** / **Data Collection Time**: < 500ms
- **页面渲染时间** / **Page Render Time**: < 1秒
- **自动刷新间隔** / **Auto-refresh Interval**: 最小 10 秒 / Minimum 10 seconds

### 安全要求 / Security Requirements
- 所有监控数据需要管理员权限才能访问 / All monitoring data requires admin permission
- 系统敏感信息（如主机名）需要脱敏处理（可选） / Sensitive system info (like hostname) needs masking (optional)

### 可用性要求 / Usability Requirements
- **数据展示**: 使用图表和进度条可视化关键指标 / **Data Display**: Use charts and progress bars to visualize key metrics
- **响应式设计**: 支持桌面和平板访问 / **Responsive Design**: Support desktop and tablet access
- **加载状态**: 显示数据加载中的提示 / **Loading State**: Show loading indicator

## 技术实现方案 / Technical Implementation

### 技术栈 / Technology Stack
- **系统信息采集** / **System Info Collection**: `psutil` - 跨平台系统信息库
- **数据展示** / **Data Display**: Jinja2 模板 + Tailwind CSS
- **实时刷新** / **Real-time Refresh**: JavaScript fetch API / htmx
- **图表展示** / **Charts**: Chart.js 或纯 CSS 进度条（可选）

### 架构设计 / Architecture Design

#### 后端结构 / Backend Structure
```
backend/app/admin/
├── monitoring.py              # 新增：监控数据服务模块
│   ├── SystemMonitorService   # 系统监控服务类
│   └── metrics schemas        # 监控指标数据结构
├── router.py                  # 更新：添加监控 API 端点
└── templates/
    ├── monitoring.html        # 更新：监控页面模板
    └── components/
        └── monitoring_metrics.html  # 新增：监控指标组件
```

#### API 端点 / API Endpoints
```
GET /super/monitoring                    # 监控页面（现有）
GET /api/monitoring/system-info          # 系统基础信息
GET /api/monitoring/cpu                  # CPU 指标
GET /api/monitoring/memory               # 内存指标
GET /api/monitoring/disk                 # 磁盘指标
GET /api/monitoring/network              # 网络指标
GET /api/monitoring/all                  # 所有指标（综合接口）
```

### 数据模型 / Data Models

```python
from pydantic import BaseModel
from typing import List, Optional

class SystemInfo(BaseModel):
    """系统基础信息 / System Basic Information"""
    hostname: str
    os_type: str
    os_version: str
    architecture: str
    boot_time: float
    uptime_seconds: float
    current_users: int

class CPUMetrics(BaseModel):
    """CPU 指标 / CPU Metrics"""
    usage_percent: float
    per_cpu_percent: List[float]
    user_time: float
    system_time: float
    idle_time: float
    context_switches: int
    interrupts: int
    load_average_1min: float
    load_average_5min: float
    load_average_15min: float

class MemoryMetrics(BaseModel):
    """内存指标 / Memory Metrics"""
    total_gb: float
    used_gb: float
    available_gb: float
    percent: float
    buffered_gb: float
    cached_gb: float
    swap_total_gb: float
    swap_used_gb: float
    swap_percent: float

class DiskPartition(BaseModel):
    """磁盘分区 / Disk Partition"""
    device: str
    mountpoint: str
    fstype: str
    total_gb: float
    used_gb: float
    free_gb: float
    percent: float

class DiskMetrics(BaseModel):
    """磁盘指标 / Disk Metrics"""
    partitions: List[DiskPartition]
    read_bytes: int
    write_bytes: int
    read_count: int
    write_count: int

class NetworkInterface(BaseModel):
    """网络接口 / Network Interface"""
    name: str
    is_up: bool
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errors_in: int
    errors_out: int
    drop_in: int
    drop_out: int

class NetworkMetrics(BaseModel):
    """网络指标 / Network Metrics"""
    interfaces: List[NetworkInterface]

class SystemMetrics(BaseModel):
    """综合指标 / All Metrics"""
    system_info: SystemInfo
    cpu: CPUMetrics
    memory: MemoryMetrics
    disk: DiskMetrics
    network: NetworkMetrics
    timestamp: float
```

### UI 设计 / UI Design

#### 页面布局 / Page Layout
```
+----------------------------------------------------------+
| 系统监控面板                    [刷新] [自动刷新: 30s ▼]   |
+----------------------------------------------------------+
| 系统信息                                                    |
| [主机名] [OS] [运行时间: 5天3小时] [当前用户: 2]            |
+----------------------------------------------------------+
| CPU 使用率                    | 内存使用率                 |
| [进度条] 45%                  | [进度条] 62%              |
| 负载: 1.5 1.2 0.8             | Swap: 15%                |
+----------------------------------------------------------+
| 磁盘使用情况                                                 |
| [分区列表表格]                                               |
+----------------------------------------------------------+
| 网络流量                                                    |
| [网卡列表表格]                                               |
+----------------------------------------------------------+
```

## 任务分解 / Task Breakdown

### Backend任务 / Backend Tasks
- [ ] [TASK-B-001] 创建监控服务模块 `monitoring.py`
  - **负责人**: Backend Developer
  - **验收标准** / **Acceptance Criteria**:
    - [ ] 创建 `SystemMonitorService` 类
    - [ ] 实现所有监控指标采集方法
    - [ ] 定义数据模型 schemas
    - [ ] 添加单元测试
  - **依赖** / **Dependencies**: 无
  - **状态**: Todo

- [ ] [TASK-B-002] 实现 API 端点
  - **负责人**: Backend Developer
  - **验收标准** / **Acceptance Criteria**:
    - [ ] 实现 `/api/monitoring/all` 综合接口
    - [ ] 实现各指标独立接口
    - [ ] 添加缓存机制（避免频繁采集）
    - [ ] 添加错误处理
  - **依赖**: TASK-B-001
  - **状态**: Todo

- [ ] [TASK-B-003] 更新监控页面模板
  - **负责人**: Backend Developer
  - **验收标准** / **Acceptance Criteria**:
    - [ ] 更新 `monitoring.html` 页面
    - [ ] 添加系统信息展示区域
    - [ ] 添加详细 CPU 指标展示
    - [ ] 添加详细内存指标展示
    - [ ] 添加磁盘分区表格
    - [ ] 添加网络接口表格
    - [ ] 实现响应式布局
  - **依赖**: TASK-B-002
  - **状态**: Todo

- [ ] [TASK-B-004] 实现实时刷新功能
  - **负责人**: Backend Developer
  - **验收标准** / **Acceptance Criteria**:
    - [ ] 添加自动刷新 JavaScript 代码
    - [ ] 添加刷新间隔选择器
    - [ ] 显示数据更新时间戳
    - [ ] 添加加载状态提示
  - **依赖**: TASK-B-003
  - **状态**: Todo

### 测试任务 / Testing Tasks
- [ ] [TASK-T-001] 编写监控服务测试
  - **负责人**: Test Engineer
  - **验收标准** / **Acceptance Criteria**:
    - [ ] 测试各平台兼容性（Linux, Windows, macOS）
    - [ ] 测试异常处理（如磁盘读取失败）
    - [ ] 测试数据准确性
    - [ ] 测试 API 响应时间
  - **依赖**: TASK-B-002
  - **状态**: Todo

## 验收标准 / Acceptance Criteria

### 整体验收 / Overall Acceptance
- [ ] 所有功能需求已实现
- [ ] 支持 Linux、Windows、macOS 三大平台
- [ ] 数据采集时间 < 500ms
- [ ] 页面响应时间 < 2秒

### 用户验收标准 / User Acceptance Criteria
- [ ] 管理员可以查看系统基础信息
- [ ] 管理员可以查看 CPU 各核心使用率
- [ ] 管理员可以查看内存详细使用情况
- [ ] 管理员可以查看所有磁盘分区使用情况
- [ ] 管理员可以查看网络接口流量
- [ ] 支持手动刷新监控数据
- [ ] 支持自动刷新并配置间隔
- [ ] 页面在桌面和平板上正常显示

### 技术验收标准 / Technical Acceptance Criteria
- [ ] 代码通过 black、mypy、flake8 检查
- [ ] 单元测试覆盖率 > 80%
- [ ] API 接口文档完整
- [ ] 无内存泄漏问题
- [ ] 跨平台兼容性测试通过

## 设计约束 / Design Constraints

### 技术约束 / Technical Constraints
- 必须使用 `psutil` 库获取系统信息
- 必须兼容 Linux、Windows、macOS 平台
- 必须遵循项目的 DDD 架构模式
- 数据采集不能影响主应用性能

### 业务约束 / Business Constraints
- 只有管理员角色可以访问监控数据
- 监控数据不持久化存储（实时采集）
- 数据展示延迟最小化

## 风险评估 / Risk Assessment

### 技术风险 / Technical Risks
| 风险项 / Risk | 概率 / Probability | 影响 / Impact | 缓解措施 / Mitigation |
|---------------|-------------------|---------------|----------------------|
| 跨平台兼容性问题 | 中 | 中 | 在各平台充分测试 |
| 频繁采集影响性能 | 低 | 中 | 添加缓存机制 |
| psutil 在某些平台不可用 | 低 | 低 | 提供降级方案 |

### 业务风险 / Business Risks
| 风险项 / Risk | 概率 / Probability | 影响 / Impact | 缓解措施 / Mitigation |
|---------------|-------------------|---------------|----------------------|
| 敏感信息泄露 | 低 | 高 | 仅管理员可访问 |

## 依赖关系 / Dependencies

### 外部依赖 / External Dependencies
- `psutil` - 系统信息采集库（已在项目中使用）
- `platform` - Python 标准库
- `os` - Python 标准库

### 内部依赖 / Internal Dependencies
- `app/admin/dependencies.py` - 认证依赖
- `app/admin/router.py` - 路由注册
- `app/core/config.py` - 配置管理

## 参考资源 / References
- [Prometheus node_exporter 文档](https://github.com/prometheus/node_exporter)
- [psutil 官方文档](https://psutil.readthedocs.io/)

## 变更记录 / Change Log

| 版本 | 日期 | 变更内容 | 变更人 | 审批人 |
|------|------|----------|--------|--------|
| 1.0 | 2026-01-12 | 初始创建 | Product Manager | - |

---

**注意 / Note**: 本需求文档定义了系统监控增强功能的完整需求，参考 Prometheus node_exporter 的指标体系，请严格按照需求进行开发和测试。

This requirements document defines the complete requirements for system monitoring enhancement, referencing the Prometheus node_exporter metrics system. Please develop and test strictly according to the requirements.
