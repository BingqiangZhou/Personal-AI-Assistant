# 日志系统优化需求文档

## 1. 需求概述

**需求ID**: LOGGING-001
**创建日期**: 2025-12-26
**状态**: 已完成
**完成日期**: 2025-12-26
**优先级**: 高

### 1.1 需求背景

当前后台日志系统存在以下问题：
- 没有统一的日志配置管理
- 日志仅输出到控制台，无法持久化
- 缺少按日期分割的日志文件
- 没有专门的错误日志文件
- 时区使用UTC，不便国内用户查看
- 日志级别使用不规范，有些地方日志过多，有些关键步骤缺少日志

### 1.2 需求目标

1. **统一日志配置**：建立集中的日志配置模块
2. **按日期分割日志**：日志文件按日期命名（如 `app-2025-12-26.log`）
3. **错误日志分离**：错误信息同时记录到专用错误文件（如 `app-2025-12-26_error.log`）
4. **时区配置**：支持通过Docker配置时区（默认使用上海时区）
5. **优化日志内容**：只保留关键日志，补充缺失的重要日志
6. **日志格式规范**：统一的日志格式，包含时间、级别、模块、消息

## 2. 用户故事

### 2.1 主要用户故事

**故事1: 日志持久化与查询**
> 作为运维人员，我希望日志能够持久化存储到文件中，并且按日期自动分割，这样我可以方便地查询历史日志。

**验收标准**:
- 日志自动写入 `logs/app-YYYY-MM-DD.log` 文件
- 每天自动创建新的日志文件
- 旧日志文件自动保留（可配置保留天数）

**故事2: 错误快速定位**
> 作为开发人员，我希望所有错误信息能够单独记录到专门的错误日志文件中，这样我可以快速定位和排查问题。

**验收标准**:
- 所有ERROR及以上级别的日志同时写入 `logs/app-YYYY-MM-DD_error.log`
- 错误日志包含完整的堆栈信息

**故事3: 时区本地化**
> 作为国内用户，我希望日志时间使用上海时区（Asia/Shanghai），这样我看日志时不需要换算时区。

**验收标准**:
- 日志时间显示为上海时区
- 支持通过Docker环境变量配置时区

**故事4: 日志内容优化**
> 作为开发人员，我希望日志内容简洁明了，只记录关键信息，这样日志不会被过多无用信息淹没。

**验收标准**:
- 移除不必要的DEBUG日志
- API请求/响应添加适当日志
- 关键业务操作添加INFO级别日志
- 异常情况添加ERROR级别日志

## 3. 功能需求

### 3.1 核心功能

#### 3.1.1 日志配置模块 (F001)
**描述**: 创建统一的日志配置模块

**实现细节**:
- 文件位置: `backend/app/core/logging_config.py`
- 使用 Python logging 模块的 TimedRotatingFileHandler
- 配置日志格式: `[%(asctime)s] [%(levelname)s] [%(name)s:%(lineno)d] %(message)s`
- 时间格式: `%Y-%m-%d %H:%M:%S`

#### 3.1.2 按日期分割日志 (F002)
**描述**: 日志文件按日期自动分割

**实现细节**:
- 文件命名: `logs/app-YYYY-MM-DD.log`
- 使用 `TimedRotatingFileHandler` with `when='midnight'`
- 日志目录: `backend/logs/`

#### 3.1.3 错误日志分离 (F003)
**描述**: 错误日志单独记录

**实现细节**:
- 文件命名: `logs/app-YYYY-MM-DD_error.log`
- 使用单独的 FileHandler 只处理 ERROR 及以上级别
- 配置 Formatter 包含完整的堆栈信息

#### 3.1.4 时区配置 (F004)
**描述**: 支持时区配置，默认使用上海时区

**实现细节**:
- 使用 `pytz` 或 `zoneinfo` 处理时区
- 环境变量: `TZ=Asia/Shanghai`
- 在 Docker Compose 中配置时区环境变量
- 日志 Formatter 中使用配置的时区

#### 3.1.5 日志内容优化 (F005)
**描述**: 优化现有代码中的日志使用

**实现细节**:
- 添加 API 请求/响应日志（中间件）
- 添加数据库连接/断开日志
- 添加 Celery 任务开始/完成/失败日志
- 移除不必要的 DEBUG 日志
- 确保所有异常都有适当的错误日志

### 3.2 配置需求

#### 3.2.1 环境变量配置 (C001)

```bash
# .env 新增配置
LOG_LEVEL=INFO                    # 日志级别: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_DIR=logs                      # 日志目录
LOG_RETENTION_DAYS=30             # 日志保留天数
TZ=Asia/Shanghai                  # 时区
```

#### 3.2.2 Docker Compose 配置 (C002)

在 `docker-compose.podcast.yml` 中为所有服务添加时区配置：

```yaml
environment:
  - TZ=Asia/Shanghai
  - LOG_LEVEL=INFO
volumes:
  - ./backend/logs:/app/logs
```

### 3.3 API 日志中间件 (F006)

**描述**: 添加请求日志中间件

**实现细节**:
- 记录请求方法、路径、状态码
- 记录请求处理时间
- 不记录健康检查请求（/health）
- 文件位置: `backend/app/core/logging_middleware.py`

## 4. 技术要求

### 4.1 技术栈
- Python logging 模块
- pytz 或 zoneinfo（Python 3.9+ 内置）
- Docker 环境变量配置

### 4.2 文件结构
```
backend/
├── app/
│   └── core/
│       ├── logging_config.py      # 日志配置（新建）
│       └── logging_middleware.py  # 日志中间件（新建）
├── logs/                          # 日志目录（新建）
│   ├── app-YYYY-MM-DD.log
│   └── app-YYYY-MM-DD_error.log
└── .env                          # 添加日志配置
```

### 4.3 日志级别使用规范

| 级别 | 使用场景 |
|------|----------|
| DEBUG | 详细的调试信息（生产环境默认关闭） |
| INFO | 关键业务操作、服务启动/关闭 |
| WARNING | 可恢复的异常情况 |
| ERROR | 错误异常，但服务可继续运行 |
| CRITICAL | 严重错误，可能导致服务中断 |

## 5. 实现计划

### 5.1 任务分解

| 任务ID | 任务描述 | 优先级 |
|--------|----------|--------|
| T001 | 创建日志配置模块 `logging_config.py` | 高 |
| T002 | 创建 API 日志中间件 `logging_middleware.py` | 高 |
| T003 | 更新 Docker Compose 配置（时区、日志卷） | 高 |
| T004 | 优化 `app/main.py` 日志 | 中 |
| T005 | 优化 `app/domains/podcast/services.py` 日志 | 中 |
| T006 | 优化 `app/domains/podcast/tasks.py` 日志 | 中 |
| T007 | 优化 `app/core/exceptions.py` 日志 | 中 |
| T008 | 更新 `.env.example` 添加日志配置 | 低 |

### 5.2 实施顺序

1. **阶段1**: 基础设施
   - T001: 创建日志配置模块
   - T002: 创建日志中间件
   - T003: 更新 Docker 配置

2. **阶段2**: 日志优化
   - T004-T007: 优化各模块日志

3. **阶段3**: 文档更新
   - T008: 更新配置文档

## 6. 验收标准

### 6.1 功能验收

- [x] 日志文件在 `backend/logs/` 目录下创建
- [x] 普通日志文件命名格式正确: `app.log` (使用 TimedRotatingFileHandler 自动添加日期后缀)
- [x] 错误日志文件命名格式正确: `app_error.log` (使用 TimedRotatingFileHandler 自动添加日期后缀)
- [x] 日志时间使用上海时区 (UTC+8)
- [x] API 请求有适当的日志记录 (中间件已添加)
- [x] 错误日志包含完整堆栈信息 (使用 exc_info=True)
- [x] 旧日志文件可以自动清理 (配置了 backupCount)

### 6.2 性能验收

- [x] 日志不影响 API 响应时间（使用标准 logging 模块）
- [x] 日志文件轮换不影响服务运行 (TimedRotatingFileHandler)

### 6.3 兼容性验收

- [x] Docker 容器内日志配置正确 (docker-compose 已更新)
- [x] 本地开发环境日志正常工作 (测试通过)
- [x] Celery Worker 日志配置正确 (tasks.py 已更新)

## 7. 实施总结

### 7.1 完成的任务

| 任务ID | 任务描述 | 状态 |
|--------|----------|------|
| T001 | 创建日志配置模块 `logging_config.py` | ✅ 已完成 |
| T002 | 创建 API 日志中间件 `logging_middleware.py` | ✅ 已完成 |
| T003 | 更新 Docker Compose 配置（时区、日志卷） | ✅ 已完成 |
| T004 | 优化 `app/main.py` 日志 | ✅ 已完成 |
| T005 | 优化 `app/domains/podcast/services.py` 日志 | ✅ 已完成 |
| T006 | 优化 `app/domains/podcast/tasks.py` 日志 | ✅ 已完成 |
| T007 | 优化 `app/core/exceptions.py` 日志 | ✅ 已完成 |
| T008 | 更新 `.env.example` 添加日志配置 | ✅ 已完成 |

### 7.2 创建的文件

1. `backend/app/core/logging_config.py` - 统一日志配置模块
2. `backend/app/core/logging_middleware.py` - API 请求日志中间件
3. `backend/logs/` - 日志目录 (运行时创建)

### 7.3 修改的文件

1. `backend/app/main.py` - 添加日志配置和中间件
2. `backend/app/core/exceptions.py` - 优化错误日志格式
3. `backend/app/domains/podcast/services.py` - 移除不必要的 DEBUG 日志
4. `backend/app/domains/podcast/tasks.py` - 添加日志配置导入
5. `backend/.env.example` - 添加日志配置说明
6. `docker/docker-compose.podcast.yml` - 添加时区和日志卷配置

### 7.4 日志格式示例

```
[2025-12-26 14:16:36] [INFO] [app.main:22] 启动 Personal AI Assistant v1.0.0 - 环境: development
[2025-12-26 14:16:36] [INFO] [test:11] 这是一条测试日志 - 普通信息
[2025-12-26 14:16:36] [WARNING] [test:12] 这是一条测试日志 - 警告
[2025-12-26 14:16:36] [ERROR] [test:13] 这是一条测试日志 - 错误
```

### 7.5 配置说明

在 `.env` 文件中添加以下配置：

```bash
# 日志配置
LOG_LEVEL=INFO              # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_DIR=logs                # Directory for log files
LOG_RETENTION_DAYS=30       # Number of days to keep old logs
TZ=Asia/Shanghai            # Timezone for log timestamps
```

## 8. 风险与注意事项

1. **日志文件大小**: 已配置 `backupCount=30` 保留30天的日志
2. **性能影响**: 使用标准 logging 模块，性能影响最小
3. **时区问题**: 使用自定义 TimezoneFormatter 不依赖外部库，兼容性更好
4. **文件权限**: Docker 卷挂载确保正确的日志文件写入权限

## 9. 参考文档

- Python Logging Cookbook: https://docs.python.org/3/howto/logging-cookbook.html
- TimedRotatingFileHandler: https://docs.python.org/3/library/logging.handlers.html
- FastAPI Middleware: https://fastapi.tiangolo.com/tutorial/middleware/

---

**变更历史**:
| 日期 | 版本 | 变更内容 | 作者 |
|------|------|----------|------|
| 2025-12-26 | 1.0 | 初始版本 | Product Manager |
| 2025-12-26 | 1.1 | 实施完成，所有任务已完成 | Product Manager |
