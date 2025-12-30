# 任务跟踪 / Task Tracking

**文档版本 / Version**: 1.0
**更新时间 / Updated**: 2025-12-30

---

## 🎯 功能: 服务器地址设置功能增强

**需求文档**: `specs/active/server-settings-enhancement.md`
**优先级**: P1 (高)
**状态**: 📋 进行中 / In Progress

---

## 📋 任务列表 / Task List

### ✅ 已完成 / Completed

| 任务 ID | 描述 | 负责人 | 完成时间 |
|---------|------|--------|----------|
| - | 需求分析并创建需求文档 | Product Manager 📋 | 2025-12-30 |

### 🔄 进行中 / In Progress

| 任务 ID | 描述 | 负责人 | 状态 |
|---------|------|--------|------|
| TASK-001 | 设置页面服务器配置增强 | Frontend Dev 🖥️ | 待开始 |
| TASK-002 | 登录页面服务器配置对话框 | Frontend Dev 🖥️ | 待开始 |
| TASK-003 | 编写 Widget 测试 | Test Engineer 🧪 | 待开始 |

### ⏳ 待开始 / Pending

| 任务 ID | 描述 | 负责人 | 依赖 |
|---------|------|--------|------|
| TASK-004 | 编写单元测试 | Test Engineer 🧪 | TASK-001, TASK-002 |
| TASK-005 | 手动测试和验收 | Product Manager 📋 | TASK-003, TASK-004 |

---

## 📝 任务详情 / Task Details

### TASK-001: 设置页面服务器配置增强

**负责人**: Frontend Developer 🖥️
**文件**: `lib/features/settings/presentation/pages/settings_page.dart`
**预估**: 2-3 小时

**子任务**:
- [ ] 移除隐藏的服务器配置功能（版本号5次点击）
- [ ] 在设置页面最上方添加服务器配置卡片
- [ ] 实现连接状态显示组件
- [ ] 实现恢复默认按钮功能
- [ ] 添加"使用本地地址"快捷按钮
- [ ] 实现测试连接功能
- [ ] 实现保存配置功能
- [ ] 支持中英文双语

**验收标准**:
- [ ] 设置页面最上方显示服务器配置卡片
- [ ] 显示当前服务器地址和连接状态
- [ ] "恢复默认"按钮功能正常
- [ ] "测试连接"显示实时状态
- [ ] "保存"按钮保存配置并立即生效
- [ ] 符合 Material 3 设计规范

---

### TASK-002: 登录页面服务器配置对话框

**负责人**: Frontend Developer 🖥️
**文件**: `lib/features/auth/view/login_screen.dart`
**预估**: 2-3 小时

**子任务**:
- [ ] 在登录页面 AppBar 添加服务器设置图标
- [ ] 创建服务器配置对话框组件
- [ ] 实现对话框 UI（与设置页面功能一致）
- [ ] 实现恢复默认按钮
- [ ] 实现保存后刷新登录状态
- [ ] 支持移动端和桌面端布局
- [ ] 支持中英文双语

**验收标准**:
- [ ] 登录页面右上角显示服务器设置图标
- [ ] 点击图标弹出服务器配置对话框
- [ ] 对话框包含所有必需的设置选项
- [ ] "恢复默认"按钮功能正常
- [ ] 保存后关闭对话框并刷新状态

---

### TASK-003: 编写 Widget 测试

**负责人**: Test Engineer 🧪
**文件**: `test/widget/features/settings/` 和 `test/widget/features/auth/`
**预估**: 2 小时

**子任务**:
- [ ] 创建 `settings_page_server_config_test.dart`
- [ ] 测试服务器配置卡片显示
- [ ] 测试连接状态更新
- [ ] 测试恢复默认功能
- [ ] 创建 `login_screen_server_config_test.dart`
- [ ] 测试服务器设置图标显示
- [ ] 测试对话框显示和功能
- [ ] 测试恢复默认按钮

**验收标准**:
- [ ] 所有 Widget 测试通过
- [ ] 测试覆盖率达到 80% 以上
- [ ] 中英文双语测试通过

---

### TASK-004: 编写单元测试

**负责人**: Test Engineer 🧪
**文件**: `test/unit/features/settings/`
**预估**: 1-2 小时

**子任务**:
- [ ] 创建 `server_config_notifier_test.dart`
- [ ] 测试恢复默认逻辑
- [ ] 测试保存配置逻辑
- [ ] 测试连接测试逻辑
- [ ] 测试 URL 标准化逻辑

**验收标准**:
- [ ] 所有单元测试通过
- [ ] 测试覆盖核心业务逻辑

---

### TASK-005: 手动测试和验收

**负责人**: Product Manager 📋
**预估**: 1 小时

**子任务**:
- [ ] 在设置页面测试服务器配置
- [ ] 在登录页面测试服务器配置对话框
- [ ] 测试恢复默认功能
- [ ] 测试连接失败场景
- [ ] 验证中英文双语
- [ ] 验证 Material 3 设计规范
- [ ] 更新需求文档状态为"已完成"

**验收标准**:
- [ ] 所有功能按需求正常工作
- [ ] 用户体验符合预期
- [ ] 通过所有验收标准

---

## 🔄 工作流程 / Workflow

```
Product Manager (需求分析) ✅
    ↓
Frontend Developer (TASK-001 & TASK-002) 🔄
    ↓
Test Engineer (TASK-003 & TASK-004) ⏳
    ↓
Product Manager (TASK-005 - 验收) ⏳
    ↓
需求文档状态更新为 "已完成"
```

---

## 📊 进度跟踪 / Progress Tracking

**总体进度**: 10% (1/10 子任务完成)

**各角色进度**:
- Product Manager: ✅ 需求分析完成
- Frontend Developer: ⏳ 待开始
- Test Engineer: ⏳ 待开始

---

## 🚀 下一步行动 / Next Actions

1. **立即行动**: 分配 TASK-001 和 TASK-002 给 Frontend Developer
2. **并行准备**: Test Engineer 准备测试框架
3. **后续安排**: Frontend 完成后立即开始测试

---

**最后更新**: 2025-12-30 by Product Manager 📋
