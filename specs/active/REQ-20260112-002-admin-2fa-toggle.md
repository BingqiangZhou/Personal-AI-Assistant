# Admin 2FA Toggle Configuration / 后台管理2FA开关配置

## 基本信息 / Basic Information
- **需求ID**: REQ-20260112-002
- **创建日期**: 2025-01-12
- **最后更新**: 2025-01-12
- **负责人**: Product Manager
- **状态**: Completed
- **优先级**: Medium

## 需求描述 / Requirements Description

### 用户故事 / User Story
作为 **系统管理员**，我想要 **通过后台UI界面控制后台管理是否启用2FA验证**，以便 **在不修改环境变量的情况下灵活调整安全级别**。

As a **system administrator**, I want to **control whether admin panel 2FA is enabled via admin UI**, so that **I can flexibly adjust security levels without modifying environment variables**.

### 业务价值 / Business Value
- 允许通过UI界面快速切换2FA开关，无需重启服务
- 环境变量提供默认值，数据库设置可覆盖环境变量
- 提供更好的用户体验和管理便利性
- Allows quick 2FA toggle via UI without service restart
- Environment variable provides default, database setting can override
- Provides better user experience and management convenience

### 背景信息 / Background
- **当前状况**: 已实现环境变量 `ADMIN_2FA_ENABLED` 控制2FA开关
- **用户需求**: 希望在后台系统设置页面添加UI按钮来控制2FA
- **机会点**: 通过数据库存储2FA设置，优先级高于环境变量
- **Current Situation**: Environment variable `ADMIN_2FA_ENABLED` controls 2FA toggle
- **User Request**: Want UI button in admin settings to control 2FA
- **Opportunity**: Store 2FA setting in database, with higher priority than environment variable

## 功能需求 / Functional Requirements

### 核心功能 / Core Features
- [FR-001] 在系统设置页面添加2FA开关UI / Add 2FA toggle UI in system settings page
- [FR-002] 添加API端点读取2FA设置 / Add API endpoint to read 2FA settings
- [FR-003] 添加API端点保存2FA设置 / Add API endpoint to save 2FA settings
- [FR-004] 数据库设置优先级高于环境变量 / Database setting takes priority over environment variable

### 功能详述 / Feature Details

#### 功能1: UI 2FA开关 / UI 2FA Toggle
- **描述**: 在系统设置页面添加安全设置卡片，包含2FA开关
- **Description**: Add security settings card in system settings page with 2FA toggle
- **UI组件**: Toggle switch (开关按钮)
- **状态显示**: 启用/禁用 (Enabled/Disabled)
- **保存方式**: 实时保存或点击保存按钮

#### 功能2: API端点 - 读取设置 / API Endpoint - Read Settings
- **描述**: GET `/super/settings/api/security` 返回当前2FA设置
- **Description**: GET `/super/settings/api/security` returns current 2FA settings
- **响应格式**: `{ "admin_2fa_enabled": true/false, "source": "database" | "env" }`

#### 功能3: API端点 - 保存设置 / API Endpoint - Save Settings
- **描述**: POST `/super/settings/api/security` 保存2FA设置
- **Description**: POST `/super/settings/api/security` saves 2FA settings
- **请求体**: `{ "admin_2fa_enabled": true/false }`
- **存储位置**: SystemSettings 表，key=`admin.2fa_enabled`

#### 功能4: 配置优先级 / Configuration Priority
- **优先级**: 数据库设置 > 环境变量默认值
- **逻辑**:
  1. 首先检查数据库中是否有 `admin.2fa_enabled` 设置
  2. 如果没有，使用环境变量 `ADMIN_2FA_ENABLED` 作为默认值
  3. 保存到数据库后，使用数据库值

## 任务分解 / Task Breakdown

### Backend任务 / Backend Tasks
- [x] [TASK-B-001] 在 `config.py` 中添加 `ADMIN_2FA_ENABLED` 配置项
- [x] [TASK-B-002] 在 `.env.example` 中添加配置示例
- [x] [TASK-B-003] 修改登录路由逻辑以支持2FA开关
- [x] [TASK-B-004] 修改认证依赖以支持2FA开关
- [x] [TASK-B-005] 添加日志记录
- [ ] [TASK-B-006] 添加 `get_admin_2fa_enabled` 辅助函数，实现优先级逻辑
- [ ] [TASK-B-007] 添加 GET `/super/settings/api/security` API端点
- [ ] [TASK-B-008] 添加 POST `/super/settings/api/security` API端点
- [ ] [TASK-B-009] 修改登录和依赖逻辑使用新的辅助函数

### Frontend任务 / Frontend Tasks
- [ ] [TASK-F-001] 在 `settings.html` 添加安全设置卡片
- [ ] [TASK-F-002] 添加2FA开关UI组件
- [ ] [TASK-F-003] 添加JavaScript加载和保存2FA设置

### 测试任务 / Testing Tasks
- [ ] [TASK-T-001] 验证数据库设置优先级
- [ ] [TASK-T-002] 验证UI开关功能
- [ ] [TASK-T-003] 验证登录流程

## 非功能需求 / Non-Functional Requirements

### 安全要求 / Security Requirements
- 默认值必须为 `true`（启用2FA）/ Default value must be `true` (2FA enabled)
- 配置变更需要重启服务生效 / Configuration change requires service restart to take effect
- 当2FA被禁用时，应在日志中记录警告 / When 2FA is disabled, a warning should be logged

### 兼容性要求 / Compatibility Requirements
- 向后兼容：不破坏现有2FA功能 / Backward compatible: does not break existing 2FA functionality
- 现有已启用2FA的用户不受影响 / Existing users with 2FA enabled are not affected

## 任务分解 / Task Breakdown

### Backend任务 / Backend Tasks
- [ ] [TASK-B-001] 在 `config.py` 中添加 `ADMIN_2FA_ENABLED` 配置项
  - **负责人**: Backend Developer
  - **文件**: `backend/app/core/config.py`
  - **验收标准**:
    - [ ] 添加 `ADMIN_2FA_ENABLED: bool = True` 配置项
    - [ ] 支持从环境变量读取
    - [ ] 默认值为 `True`
  - **状态**: Todo

- [ ] [TASK-B-002] 在 `.env.example` 中添加配置示例
  - **负责人**: Backend Developer
  - **文件**: `backend/.env.example`
  - **验收标准**:
    - [ ] 添加 `ADMIN_2FA_ENABLED=true` 配置项及注释说明
  - **状态**: Todo

- [ ] [TASK-B-003] 修改登录路由逻辑以支持2FA开关
  - **负责人**: Backend Developer
  - **文件**: `backend/app/admin/router.py`
  - **验收标准**:
    - [ ] 修改 `/super/login` POST 路由
    - [ ] 根据 `ADMIN_2FA_ENABLED` 配置决定是否进行2FA验证
    - [ ] 当2FA禁用时，直接创建会话
  - **状态**: Todo

- [ ] [TASK-B-004] 修改认证依赖以支持2FA开关
  - **负责人**: Backend Developer
  - **文件**: `backend/app/admin/dependencies.py`
  - **验收标准**:
    - [ ] 修改 `AdminAuthRequired` 类，增加对全局2FA开关的检查
    - [ ] 当全局2FA禁用时，不强制要求用户启用2FA
    - [ ] 保持向后兼容性
  - **状态**: Todo

- [ ] [TASK-B-005] 添加日志记录
  - **负责人**: Backend Developer
  - **文件**: `backend/app/admin/router.py`, `backend/app/admin/dependencies.py`
  - **验收标准**:
    - [ ] 当2FA被禁用时，记录警告日志
    - [ ] 登录时记录2FA状态
  - **状态**: Todo

### 测试任务 / Testing Tasks
- [ ] [TASK-T-001] 验证2FA启用时的登录流程
  - **负责人**: Test Engineer
  - **验收标准**:
    - [ ] 设置 `ADMIN_2FA_ENABLED=true`
    - [ ] 验证登录流程正常要求2FA
    - [ ] 验证已启用2FA的用户正常登录
  - **状态**: Todo

- [ ] [TASK-T-002] 验证2FA禁用时的登录流程
  - **负责人**: Test Engineer
  - **验收标准**:
    - [ ] 设置 `ADMIN_2FA_ENABLED=false`
    - [ ] 验证登录流程跳过2FA验证
    - [ ] 验证用户可以直接登录后台
  - **状态**: Todo

## 验收标准 / Acceptance Criteria

### 整体验收 / Overall Acceptance
- [ ] 所有功能需求已实现 / All functional requirements implemented
- [ ] 代码质量达标 / Code quality standards met
- [ ] 测试通过 / Tests passed

### 用户验收标准 / User Acceptance Criteria
- [ ] 设置 `ADMIN_2FA_ENABLED=true` 时，登录需要验证2FA
- [ ] 设置 `ADMIN_2FA_ENABLED=false` 时，登录不需要验证2FA
- [ ] 默认配置（不设置环境变量）下，2FA保持启用
- [ ] When `ADMIN_2FA_ENABLED=true`, login requires 2FA verification
- [ ] When `ADMIN_2FA_ENABLED=false`, login does not require 2FA verification
- [ ] Default configuration (no env var set) keeps 2FA enabled

### 技术验收标准 / Technical Acceptance Criteria
- [ ] 代码通过 linting 检查 / Code passes linting checks
- [ ] 添加适当的日志记录 / Appropriate logging added
- [ ] 向后兼容性保持 / Backward compatibility maintained

## 设计约束 / Design Constraints

### 技术约束 / Technical Constraints
- 必须使用 FastAPI 现有架构 / Must use existing FastAPI architecture
- 配置通过环境变量传递 / Configuration passed via environment variables
- 不修改数据库 schema / No database schema modifications

### 安全约束 / Security Constraints
- 默认值必须为启用2FA / Default value must be 2FA enabled
- 禁用2FA时必须记录日志 / Must log when 2FA is disabled

## 风险评估 / Risk Assessment

### 技术风险 / Technical Risks
| 风险项 | 概率 | 影响 | 缓解措施 |
|--------|------|------|----------|
| 2FA禁用时安全风险 | 高 | 高 | 默认启用，文档说明风险 |
| Breaking existing 2FA flow | 中 | 中 | 充分测试，保持向后兼容 |

| Risk Item | Probability | Impact | Mitigation |
|-----------|-------------|---------|------------|
| Security risk when 2FA disabled | High | High | Default enabled, document risks |
| Breaking existing 2FA flow | Medium | Medium | Thorough testing, maintain backward compatibility |

## 时间线 / Timeline

### 里程碑 / Milestones
- **需求确认**: 2025-01-12
- **开发完成**: 2025-01-12
- **测试完成**: 2025-01-12
- **上线发布**: 2025-01-12

### 关键路径 / Critical Path
1. 添加配置项 → 修改登录逻辑 → 修改依赖注入 → 测试验证

## 变更记录 / Change History

| 版本 | 日期 | 变更内容 | 变更人 | 审批人 |
|------|------|----------|--------|--------|
| 1.0 | 2025-01-12 | 初始创建 | Product Manager | - |

## 相关文档 / Related Documents
- `backend/app/admin/router.py` - 后台管理路由
- `backend/app/admin/dependencies.py` - 认证依赖
- `backend/app/core/config.py` - 配置管理
- `backend/.env.example` - 环境变量模板

## 审批 / Approvals

### 需求评审 / Requirements Review
- [x] 产品负责人审批 - 待定
- [ ] 技术负责人审批
- [ ] QA负责人审批

---

**注意**: 本文档是工作过程中的核心文档，请及时更新并保持版本同步。
