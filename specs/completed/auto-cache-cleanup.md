# 自动清理缓存功能 / Auto Cache Cleanup Feature

**需求编号 / Requirement ID**: REQ-2025-001
**创建日期 / Created**: 2025-01-13
**最后更新 / Last Updated**: 2025-01-13
**优先级 / Priority**: High
**状态 / Status**: ✅ Completed

---

## 📋 需求概述 / Overview

### 用户故事 / User Story

**作为** 系统管理员
**我想要** 在后台管理系统设置中添加自动清理缓存功能
**以便** 自动清理旧的缓存文件，释放磁盘空间并保持系统高效运行

As a **system administrator**, I want to add **auto cache cleanup** functionality in the admin settings page, so that I can **automatically clean old cache files** to free up disk space and keep the system running efficiently.

---

## 🎯 功能需求 / Functional Requirements

### 1. 存储信息显示 / Storage Information Display

**需求描述 / Description**:
在 admin 系统设置页面添加"存储管理"卡片，实时显示以下信息：

#### 1.1 Storage 目录信息
- **文件数量**: storage 目录下所有文件的总数
- **总大小**: storage 目录占用空间（使用人类可读格式，如 MB、GB、TB）
- **最后更新**: 显示最后更新时间

#### 1.2 Temp 目录信息
- **文件数量**: temp 目录下所有文件的总数
- **总大小**: temp 目录占用空间
- **最后更新**: 显示最后更新时间

#### 1.3 系统磁盘信息
- **剩余空间**: 系统磁盘可用空间
- **总容量**: 系统磁盘总容量
- **使用率**: 磁盘使用百分比

### 2. 自动清理开关 / Auto Cleanup Toggle

**需求描述 / Description**:
提供自动清理开关，控制是否启用定时清理功能：

- **开关状态**: 启用/禁用（Toggle）
- **清理策略**: 每天凌晨4点执行清理
- **清理规则**: 删除昨天及之前的文件（仅保留今天的数据）
- **清理范围**: storage 和 temp 目录

### 3. 手动清理功能 / Manual Cleanup

**需求描述 / Description**:
提供手动立即清理按钮：

- **触发方式**: 点击"立即清理"按钮
- **清理范围**: storage 和 temp 目录
- **清理规则**: 删除昨天及之前的文件
- **确认对话框**: 清理前显示确认对话框

### 4. 日志记录 / Logging

**需求描述 / Description**:
后台日志需要输出详细的清理信息：

```
[INFO] 开始清理缓存文件...
[INFO] Storage 目录: 删除 X 个文件, 释放 Y MB 空间
[INFO] Temp 目录: 删除 X 个文件, 释放 Y MB 空间
[INFO] 清理完成: 总计删除 X 个文件, 释放 Y MB 空间
```

---

## 🔧 技术实现 / Technical Implementation

### 后端实现 / Backend Implementation

#### 3.1 数据模型 / Data Model

**新增配置存储** (使用现有的 `SystemSettings` 表):

```python
# Key: "auto_cache_cleanup"
{
    "enabled": bool,  # 是否启用自动清理
    "last_cleanup": "ISO 8601 datetime",  # 最后清理时间
}
```

#### 3.2 API 端点 / API Endpoints

**1. 获取存储信息 / Get Storage Info**

```
GET /api/v1/admin/storage/info
Response:
{
    "storage": {
        "file_count": 1234,
        "total_size": 1073741824,  // bytes
        "total_size_human": "1.0 GB",
        "last_updated": "2025-01-13T12:00:00Z"
    },
    "temp": {
        "file_count": 56,
        "total_size": 52428800,
        "total_size_human": "50.0 MB",
        "last_updated": "2025-01-13T12:00:00Z"
    },
    "disk": {
        "free": 536870912000,
        "free_human": "500 GB",
        "total": 1099511627776,
        "total_human": "1 TB",
        "usage_percent": 51.2
    }
}
```

**2. 获取自动清理配置 / Get Auto Cleanup Config**

```
GET /api/v1/admin/storage/cleanup/config
Response:
{
    "enabled": true,
    "last_cleanup": "2025-01-13T00:00:00Z"
}
```

**3. 更新自动清理配置 / Update Auto Cleanup Config**

```
POST /api/v1/admin/storage/cleanup/config
Body:
{
    "enabled": true
}
Response:
{
    "success": true,
    "message": "配置已更新"
}
```

**4. 手动触发清理 / Manual Cleanup Trigger**

```
POST /api/v1/admin/storage/cleanup/execute
Response:
{
    "success": true,
    "storage": {
        "deleted_count": 100,
        "freed_space": 1073741824,
        "freed_space_human": "1.0 GB"
    },
    "temp": {
        "deleted_count": 20,
        "freed_space": 52428800,
        "freed_space_human": "50.0 MB"
    },
    "total": {
        "deleted_count": 120,
        "freed_space": 1127218944,
        "freed_space_human": "1.05 GB"
    }
}
```

#### 3.3 Celery 定时任务 / Celery Scheduled Task

**添加到 `backend/app/domains/podcast/tasks.py`:**

```python
@celery_app.task
def auto_cleanup_cache_files():
    """
    自动清理缓存文件任务
    每天凌晨4点执行，清理昨天及之前的文件
    """
    # 实现清理逻辑
```

**配置到 `beat_schedule`:**

```python
'auto-cleanup-cache': {
    'task': 'app.domains.podcast.tasks.auto_cleanup_cache_files',
    'schedule': crontab(hour=4, minute=0),  # 每天凌晨4点
    'options': {'queue': 'cleanup'}
}
```

#### 3.4 文件清理服务 / File Cleanup Service

**创建新文件 `backend/app/admin/storage_service.py`:**

```python
class StorageCleanupService:
    """存储清理服务"""

    async def get_storage_info(self) -> dict:
        """获取存储信息"""

    async def execute_cleanup(self, keep_days: int = 2) -> dict:
        """执行清理操作"""
```

---

### 前端实现 (Admin HTML) / Frontend Implementation

#### 4.1 UI 组件 / UI Components

**在 `settings.html` 中添加新卡片:**

```html
<!-- Storage Management Card -->
<div class="mt-6 bg-white shadow sm:rounded-lg overflow-hidden">
    <div class="px-6 py-4 border-b border-gray-200">
        <h3 class="text-lg font-semibold text-gray-900">存储管理</h3>
    </div>
    <div class="px-6 py-6 space-y-6">
        <!-- Storage Info Display -->
        <!-- Auto Cleanup Toggle -->
        <!-- Manual Cleanup Button -->
    </div>
</div>
```

#### 4.2 JavaScript 功能 / JavaScript Functions

```javascript
// 加载存储信息
async function loadStorageInfo()

// 更新自动清理配置
async function toggleAutoCleanup()

// 手动触发清理
async function executeManualCleanup()

// 格式化文件大小
function formatBytes(bytes)

// 更新 UI 显示
function updateStorageUI(data)
```

---

## ✅ 验收标准 / Acceptance Criteria

### 1. 存储信息显示
- [ ] Storage 目录信息正确显示（文件数、大小）
- [ ] Temp 目录信息正确显示（文件数、大小）
- [ ] 系统磁盘信息正确显示（剩余空间、使用率）
- [ ] 信息实时更新

### 2. 自动清理功能
- [ ] 自动清理开关正常工作
- [ ] 配置成功保存到数据库
- [ ] Celery 定时任务正确配置
- [ ] 每天凌晨4点自动执行清理

### 3. 手动清理功能
- [ ] 手动清理按钮正常工作
- [ ] 清理前显示确认对话框
- [ ] 清理后显示成功消息
- [ ] 返回删除的文件数量和释放的空间

### 4. 日志记录
- [ ] 清理开始时输出日志
- [ ] 分别记录 storage 和 temp 的清理结果
- [ ] 输出总计删除的文件数量和空间大小
- [ ] 日志格式清晰易读

### 5. 安全性
- [ ] API 需要管理员权限
- [ ] 清理操作有审计日志
- [ ] 防止误删除重要文件

### 6. 性能
- [ ] 存储信息查询响应时间 < 1 秒
- [ ] 清理操作不影响系统正常运行
- [ ] 大量文件时也能高效处理

---

## 🗂️ 文件清单 / File Checklist

### 后端文件 / Backend Files

- [ ] `backend/app/admin/storage_service.py` - 存储清理服务
- [ ] `backend/app/admin/router.py` - 添加新的 API 路由
- [ ] `backend/app/domains/podcast/tasks.py` - 添加 Celery 定时任务
- [ ] `backend/app/admin/schemas.py` - 添加响应 schema（如果需要）

### 前端文件 / Frontend Files

- [ ] `backend/app/admin/templates/settings.html` - 添加存储管理卡片

---

## 🧪 测试计划 / Test Plan

### 单元测试 / Unit Tests

```python
# 测试存储服务
def test_get_storage_info()
def test_execute_cleanup()
def test_keep_days_parameter()
```

### 集成测试 / Integration Tests

```python
# 测试 API 端点
async def test_get_storage_info_api()
async def test_update_cleanup_config_api()
async def test_execute_cleanup_api()
```

### 手动测试 / Manual Testing

1. 访问 admin 系统设置页面
2. 验证存储信息显示正确
3. 测试自动清理开关
4. 测试手动清理功能
5. 检查后台日志输出

---

## 📝 注意事项 / Notes

1. **路径配置**:
   - storage 路径: `./storage`
   - temp 路径: `./temp`
   - 从 `settings.TRANSCRIPTION_TEMP_DIR` 和 `settings.TRANSCRIPTION_STORAGE_DIR` 获取

2. **日期判断**:
   - 使用 UTC 时间
   - 清理规则: `file_mtime < today - 2 days`

3. **错误处理**:
   - 文件正在使用中: 跳过该文件，记录警告
   - 权限不足: 记录错误，继续处理其他文件
   - 路径不存在: 记录警告，不中断流程

4. **性能优化**:
   - 使用 `os.scandir()` 代替 `os.listdir()`
   - 批量删除，减少系统调用
   - 异步处理大文件删除

---

## 🎨 UI 设计参考 / UI Design Reference

```
┌─────────────────────────────────────────────────────┐
│  系统设置                                             │
├─────────────────────────────────────────────────────┤
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │ 音频处理                              [保存] │    │
│  └─────────────────────────────────────────────┘    │
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │ RSS订阅设置                          [保存] │    │
│  └─────────────────────────────────────────────┘    │
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │ 存储管理                            [刷新] │    │
│  ├─────────────────────────────────────────────┤    │
│  │                                              │    │
│  │ 📁 Storage 目录                              │    │
│  │   文件数: 1,234                             │    │
│  │   大小: 1.0 GB                              │    │
│  │                                              │    │
│  │ 📁 Temp 目录                                 │    │
│  │   文件数: 56                                │    │
│  │   大小: 50.0 MB                             │    │
│  │                                              │    │
│  │ 💾 系统磁盘                                   │    │
│  │   剩余: 500 GB / 1 TB (51%)                 │    │
│  │                                              │    │
│  │ ─────────────────────────────────────────    │    │
│  │                                              │    │
│  │ 自动清理缓存    [ON/OFF]                     │    │
│  │ 每天凌晨4点清理昨天及之前的文件                 │    │
│  │                                              │    │
│  │ [立即清理]                                    │    │
│  │                                              │    │
│  └─────────────────────────────────────────────┘    │
│                                                       │
│  ┌─────────────────────────────────────────────┐    │
│  │ 安全设置                                       │    │
│  └─────────────────────────────────────────────┘    │
│                                                       │
└─────────────────────────────────────────────────────┘
```

---

## 📚 参考资料 / References

- Python `os` and `os.path` 文档
- `shutil` 模块用于磁盘空间查询
- Celery Beat 定时任务配置
- FastAPI 异步文件操作最佳实践

---

**最后更新 / Last Updated**: 2025-01-13
**负责人 / Owner**: Backend Developer & Admin UI Developer
