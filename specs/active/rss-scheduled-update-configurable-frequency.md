# RSS订阅定时更新配置功能需求文档

## 📋 需求概述

**需求ID**: RSS-001
**创建日期**: 2025-12-25
**状态**: 🟡 进行中
**优先级**: P1 (高)

### 需求描述

增强现有的RSS订阅定时更新功能，允许用户为每个订阅配置独立的更新频率和更新时间，并在更新后自动进行音频转录和AI总结。

---

## 🎯 用户故事

### 主要用户故事

**作为** 一个播客订阅用户
**我想要** 为每个RSS订阅设置独立的更新频率和更新时间
**以便于** 我可以根据播客的发布规律和我的个人需求优化更新检查，避免错过新内容或浪费系统资源

### 边缘用户故事

- **作为** 一个系统管理员，**我想要** 限制用户可配置的最小更新间隔，**以便于** 防止系统资源滥用
- **作为** 一个用户，**我想要** 为高频更新的播客设置更短的检查间隔，**以便于** 更快获取新内容
- **作为** 一个用户，**我想要** 为低频更新的播客设置每日定时更新，**以便于** 减少不必要的系统检查

---

## ✅ 验收标准

### 后端验收标准

#### 1. 数据模型扩展
- [ ] `PodcastSubscription` 模型添加以下字段：
  - `update_frequency`: 更新频率类型（HOURLY, DAILY, WEEKLY）
  - `update_time`: 更新时间（HH:MM格式，仅对DAILY/WEEKLY有效）
  - `update_day_of_week`: 星期几（1-7，仅对WEEKLY有效）
- [ ] 数据库迁移脚本创建并执行成功
- [ ] 现有订阅自动迁移到默认配置（HOURLY，当前时间）

#### 2. 调度系统重构
- [ ] 创建动态调度器 `DynamicScheduleManager`
- [ ] 支持基于每个订阅的独立调度配置
- [ ] 支持三种调度模式：
  - **HOURLY**: 每N小时检查一次（N可配置）
  - **DAILY**: 每天指定时间检查（如00:00, 08:00）
  - **WEEKLY**: 每周指定 day 和 time 检查（如周一09:00）
- [ ] 调度器支持运行时动态添加/移除/更新订阅调度
- [ ] 与现有Celery Beat集成或替代方案

#### 3. API接口
- [ ] `PATCH /api/v1/podcast/subscriptions/{id}/schedule` - 更新订阅调度配置
  ```json
  {
    "update_frequency": "DAILY",
    "update_time": "00:00"
  }
  ```
- [ ] `GET /api/v1/podcast/subscriptions/{id}/schedule` - 获取订阅调度配置
- [ ] 请求参数验证和错误处理
- [ ] 权限检查（只能修改自己的订阅）

#### 4. 自动转录和AI总结
- [ ] 新 episode 自动触发转录任务
- [ ] 转录完成后自动触发AI总结生成
- [ ] 失败重试机制（最多3次）
- [ ] 状态更新通知（可选）

#### 5. 测试覆盖
- [ ] 单元测试：调度逻辑测试
- [ ] 集成测试：API接口测试
- [ ] 端到端测试：完整流程测试
- [ ] 测试覆盖率 >= 80%

### 前端验收标准

#### 1. 设置页面UI
- [ ] 创建"订阅设置"页面（SubscriptionSettingsPage）
- [ ] 使用 Material 3 设计规范
- [ ] 使用 flutter_adaptive_scaffold 实现响应式布局
- [ ] 页面包含以下部分：
  - 订阅列表（显示当前配置）
  - 更新频率选择器
  - 更新时间选择器（根据频率动态显示）
  - 保存按钮

#### 2. 更新频率选择器
- [ ] 下拉菜单或分段选择器
- [ ] 支持选项：
  - **每小时** (HOURLY)
  - **每天** (DAILY)
  - **每周** (WEEKLY)
- [ ] 显示当前选中值
- [ ] 切换时动态更新时间选择器状态

#### 3. 更新时间选择器
- [ ] TimePicker 组件选择时间（HH:MM格式）
- [ ] 选择"每天"时显示时间选择器
- [ ] 选择"每周"时显示：
  - 星期几选择器（SegmentedButton）
  - 时间选择器
- [ ] 选择"每小时"时隐藏时间选择器

#### 4. 用户体验
- [ ] 保存时显示加载状态
- [ ] 保存成功显示 Snackbar 提示
- [ ] 保存失败显示错误信息
- [ ] 表单验证（如时间格式）
- [ ] 确认对话框（可选）
- [ ] 下次更新时间预览

#### 5. 响应式设计
- [ ] 桌面端：使用 NavigationRail
- [ ] 移动端：使用 BottomNavigationBar
- [ ] 平板端：自适应布局
- [ ] 所有组件在不同屏幕尺寸下正常工作

#### 6. Widget测试
- [ ] 页面渲染测试
- [ ] 加载状态测试
- [ ] 数据显示测试
- [ ] 用户交互测试（切换频率、选择时间）
- [ ] 保存功能测试
- [ ] 错误处理测试
- [ ] 测试覆盖率 >= 80%

---

## 🛠️ 技术要求

### 后端技术要求

#### 技术栈
- **调度框架**: Celery Beat + APScheduler (或替代方案)
- **数据库**: PostgreSQL + SQLAlchemy (async)
- **API**: FastAPI
- **时区处理**: pytz 或 zoneinfo

#### 架构要求
- 遵循 DDD 架构模式
- 服务层与调度逻辑分离
- 支持运行时动态配置更新
- 优雅处理调度冲突和错误
- 支持分布式部署（多worker）

#### 性能要求
- 单个调度任务执行时间 < 5秒
- 支持至少1000个并发订阅调度
- 内存使用优化，避免调度信息泄漏

#### 安全要求
- 输入验证防止注入攻击
- 权限检查确保用户只能修改自己的订阅
- 速率限制防止API滥用

### 前端技术要求

#### 技术栈
- **框架**: Flutter 3.x
- **状态管理**: Riverpod
- **路由**: GoRouter
- **UI组件**: Material 3 + flutter_adaptive_scaffold

#### 架构要求
- 遵循 Clean Architecture
- 使用 Repository 模式管理 API 调用
- 状态管理使用 Riverpod Providers
- 响应式设计支持多平台

#### 依赖项
- `flutter_adaptive_scaffold`: 响应式布局
- `intl`: 日期时间格式化
- `time_picker`: Material 3 时间选择器

---

## 📊 数据模型

### 后端数据模型扩展

```python
# app/domains/podcast/models/subscription.py

class UpdateFrequency(str, enum.Enum):
    HOURLY = "HOURLY"   # 每小时
    DAILY = "DAILY"     # 每天
    WEEKLY = "WEEKLY"   # 每周

class PodcastSubscription(Base):
    # ... 现有字段 ...

    # 新增字段
    update_frequency: str = Column(
        String(10),
        nullable=False,
        default=UpdateFrequency.HOURLY.value,
        comment="更新频率类型"
    )
    update_time: str = Column(
        String(5),
        nullable=True,
        comment="更新时间 HH:MM"
    )
    update_day_of_week: int = Column(
        Integer,
        nullable=True,
        comment="星期几 (1-7, 1=周一)"
    )

    @property
    def next_update_time(self) -> datetime:
        """计算下次更新时间"""
        # 实现调度逻辑
        pass
```

### 前端数据模型

```dart
// lib/features/podcast/data/models/subscription_model.dart

enum UpdateFrequency {
  hourly,
  daily,
  weekly;
}

class PodcastSubscriptionModel {
  // ... 现有字段 ...

  final UpdateFrequency updateFrequency;
  final String? updateTime; // HH:MM format
  final int? updateDayOfWeek; // 1-7

  // 计算下次更新时间预览
  DateTime? get nextUpdateTime => _calculateNextUpdate();
}
```

---

## 🔄 工作流程

### 更新调度流程

```
用户设置调度配置
    ↓
前端验证并调用API
    ↓
后端更新数据库
    ↓
动态调度器更新调度
    ↓
Celery Beat按配置执行
    ↓
获取RSS feeds
    ↓
检测新episodes
    ↓
自动触发转录
    ↓
自动触发AI总结
    ↓
更新episode状态
```

### 调度决策流程

```
当前时间
    ↓
遍历所有订阅
    ↓
检查订阅调度配置
    ↓
判断是否应该更新
    ├─ HOURLY: last_update + interval < now
    ├─ DAILY: current_time == update_time
    └─ WEEKLY: current_day == update_day AND current_time == update_time
    ↓
执行更新任务
```

---

## 🚫 非功能性要求

### 性能要求
- 调度配置更新响应时间 < 500ms
- 批量更新支持（最多50个订阅）
- 数据库查询优化（索引和缓存）

### 可用性要求
- 系统可用性 >= 99.5%
- 调度失败自动重试
- 降级策略（默认每小时检查）

### 可维护性要求
- 详细的日志记录
- 监控指标（调度执行次数、失败率）
- 运维工具支持（手动触发更新）

---

## 📝 API规范

### 更新订阅调度配置

**请求**
```http
PATCH /api/v1/podcast/subscriptions/{id}/schedule
Authorization: Bearer <token>
Content-Type: application/json

{
  "update_frequency": "DAILY",
  "update_time": "00:00",
  "update_day_of_week": null
}
```

**响应**
```json
{
  "id": "uuid",
  "title": "播客标题",
  "update_frequency": "DAILY",
  "update_time": "00:00",
  "update_day_of_week": null,
  "next_update_at": "2025-12-26T00:00:00Z"
}
```

### 获取订阅调度配置

**请求**
```http
GET /api/v1/podcast/subscriptions/{id}/schedule
Authorization: Bearer <token>
```

**响应**
```json
{
  "id": "uuid",
  "title": "播客标题",
  "schedule": {
    "frequency": "DAILY",
    "time": "00:00",
    "day_of_week": null,
    "next_update_at": "2025-12-26T00:00:00Z",
    "last_updated_at": "2025-12-25T00:00:00Z"
  }
}
```

---

## 🧪 测试计划

### 后端测试

#### 单元测试
- [ ] 调度逻辑计算测试
- [ ] 下次更新时间计算测试
- [ ] 不同频率类型测试
- [ ] 边界条件测试（月末、年末、闰年）

#### 集成测试
- [ ] API接口测试
- [ ] 数据库操作测试
- [ ] 调度器集成测试
- [ ] 错误处理测试

#### 端到端测试
- [ ] 完整更新流程测试
- [ ] 转录和AI总结集成测试
- [ ] 并发更新测试

### 前端测试

#### Widget测试
- [ ] 页面渲染测试
- [ ] 状态管理测试
- [ ] 用户交互测试
- [ ] 表单验证测试

#### 集成测试
- [ ] API调用测试
- [ ] 状态同步测试
- [ ] 错误处理测试

---

## 📚 参考资料

### 技术文档
- [Celery Beat - Dynamic Scheduling](https://docs.celeryq.dev/en/stable/userguide/periodic-tasks.html)
- [APScheduler - Python Job Scheduling Library](https://apscheduler.readthedocs.io/)
- [Material 3 Time Picker](https://api.flutter.dev/flutter/material/TimePicker-class.html)
- [flutter_adaptive_scaffold](https://pub.dev/packages/flutter_adaptive_scaffold)

### 现有代码
- `app/domains/podcast/` - 后端播客领域
- `lib/features/podcast/` - 前端播客功能
- `app/domains/podcast/tasks.py` - 现有Celery任务

---

## 🎬 MVP范围

### 第一阶段（核心功能）
1. 后端数据模型扩展和迁移
2. 基础调度逻辑实现（HOURLY, DAILY）
3. API接口实现
4. 前端设置页面基础UI
5. 基本测试覆盖

### 第二阶段（完整功能）
1. WEEKLY频率支持
2. 高级调度功能
3. 完整的前端UI
4. 完善测试覆盖
5. 性能优化

### 第三阶段（增强功能）
1. 批量配置
2. 调度历史记录
3. 通知和提醒
4. 高级分析和报告

---

## 📝 变更历史

| 日期 | 版本 | 变更内容 | 作者 |
|------|------|----------|------|
| 2025-12-25 | 1.0 | 初始需求文档创建 | 产品经理 |

---

## ✍️ 审批和签字

| 角色 | 姓名 | 审批状态 | 日期 |
|------|------|----------|------|
| 产品经理 | - | 🟡 待审批 | - |
| 架构师 | - | ⏸️ 待审批 | - |
| 后端工程师 | - | ⏸️ 待审批 | - |
| 前端工程师 | - | ⏸️ 待审批 | - |
