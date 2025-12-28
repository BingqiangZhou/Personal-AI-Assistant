# 需求文档：忘记密码页面返回按钮修复
# Requirement: Fix Forgot Password Page Back Navigation

**文档状态 / Document Status**: 已完成 / Completed
**创建日期 / Created**: 2025-12-28
**优先级 / Priority**: P1 - 高优先级 / High
**负责人 / Owner**: 前端工程师 / Frontend Developer
**产品经理 / Product Manager**: TBD

---

## 📋 需求概述 / Overview

### 问题描述 / Problem Description
用户点击登录页面的"忘记密码"链接进入忘记密码页面后，点击 AppBar 的返回按钮无法返回上一页（登录页面）。

**问题现象 / Symptoms:**
- 在忘记密码页面点击左上角返回按钮无响应
- 用户被迫使用其他方式返回（如关闭应用）

### 根本原因分析 / Root Cause Analysis

**技术原因 / Technical Root Cause:**

1. **登录页面导航方式** (`login_page.dart:322`):
   ```dart
   context.go('/forgot-password');
   ```
   - 使用 `go()` 方法会替换当前路由，而不是推入新路由到导航栈
   - 导航栈中没有保留 `/login` 路由

2. **忘记密码页面返回方式** (`forgot_password_page.dart:67`):
   ```dart
   leading: IconButton(
     icon: const Icon(Icons.arrow_back),
     onPressed: () => context.pop(),
   ),
   ```
   - `pop()` 方法从导航栈弹出当前路由
   - 但由于使用 `go()` 导航，栈中没有可返回的路由

**流程图 / Flow Diagram:**
```
┌─────────────┐
│  /login     │
│  Login Page │
└──────┬──────┘
       │ context.go('/forgot-password')
       │ 替换路由，无导航栈
       ↓
┌─────────────┐
│/forgot-pwd  │
│Forgot Pwd   │
└──────┬──────┘
       │ context.pop()
       │ ❌ 栈为空，无法返回
       ↓
    [无响应]
```

---

## 🎯 用户故事 / User Story

**作为 / As a** 用户
**我想要 / I want to** 在忘记密码页面能够通过返回按钮返回登录页面
**以便 / So that** 我可以方便地在两个页面之间切换

**验收标准 / Acceptance Criteria:**

- [ ] **AC1**: 点击登录页面"忘记密码"链接可以正常进入忘记密码页面
- [ ] **AC2**: 在忘记密码页面点击 AppBar 返回按钮可以返回登录页面
- [ ] **AC3**: 用户手动输入 `/forgot-password` URL 访问时，返回按钮也能正常工作
- [ ] **AC4**: 返回按钮遵循 Material Design 规范
- [ ] **AC5**: 现有的 widget 测试通过
- [ ] **AC6**: (可选) 添加新的 widget 测试覆盖返回按钮功能

---

## 🔧 技术方案 / Technical Solution

### 推荐方案 / Recommended Solution

**方案 A: 修改返回按钮导航逻辑（推荐）**

在 `forgot_password_page.dart` 中修改返回按钮逻辑：

```dart
// 修改前 / Before
leading: IconButton(
  icon: const Icon(Icons.arrow_back),
  onPressed: () => context.pop(),
),

// 修改后 / After
leading: IconButton(
  icon: const Icon(Icons.arrow_back),
  onPressed: () => context.go('/login'),
),
```

**优点 / Advantages:**
- ✅ 简单直接，只需修改一处代码
- ✅ 兼容直接 URL 访问场景
- ✅ 符合 GoRouter 设计理念（基于 URL 的导航）
- ✅ 不影响其他页面的导航逻辑

**缺点 / Disadvantages:**
- ⚠️ 如果将来忘记密码页面可以从多个入口进入，需要调整逻辑

### 备选方案 / Alternative Solution

**方案 B: 修改登录页面导航逻辑**

在 `login_page.dart` 中修改导航方式：

```dart
// 修改前 / Before
context.go('/forgot-password');

// 修改后 / After
context.push('/forgot-password');
```

同时确保路由配置支持子路由嵌套（需要调整路由结构）。

**优点 / Advantages:**
- ✅ `pop()` 可以正常工作

**缺点 / Disadvantages:**
- ❌ 需要重构路由结构（将 forgot-password 作为 login 的子路由）
- ❌ 如果用户直接访问忘记密码页面，`pop()` 仍然无法返回
- ❌ 影响范围更大，风险更高

---

## 📁 影响范围 / Impact Scope

### 需要修改的文件 / Files to Modify

| 文件路径 / File Path | 修改类型 / Change Type | 优先级 / Priority |
|----------------------|----------------------|-------------------|
| `frontend/lib/features/auth/presentation/pages/forgot_password_page.dart` | 代码修改 / Code Change | P0 |
| `frontend/test/widget/features/auth/pages/forgot_password_page_test.dart` | 测试更新 / Test Update | P1 |

### 不需要修改 / No Changes Needed

- ✅ 路由配置 (`app_router.dart`)
- ✅ 登录页面 (`login_page.dart`)
- ✅ 其他认证页面

---

## 🧪 测试计划 / Test Plan

### 单元测试 / Unit Tests
- 不涉及纯逻辑修改，无需单元测试

### Widget 测试 / Widget Tests

**新增测试场景 / New Test Scenarios:**

```dart
testWidgets(
  '[ForgotPasswordPage] tapping back button navigates to login',
  (WidgetTester tester) async {
    // 1. Build the widget
    await tester.pumpWidget(
      ProviderScope(
        overrides: [...],
        child: MaterialApp.router(
          routerConfig: appRouter,
        ),
      ),
    );

    // 2. Navigate to forgot password page
    context.go('/forgot-password');
    await tester.pumpAndSettle();

    // 3. Tap the back button
    await tester.tap(find.byIcon(Icons.arrow_back));
    await tester.pumpAndSettle();

    // 4. Verify navigation to login page
    expect(context.goRouter.location, '/login');
  },
);
```

### 集成测试 / Integration Tests
- 现有的 `test_forgot_password_flow.dart` 应该能够验证完整流程

### 手动测试 / Manual Testing

| 测试场景 / Test Case | 步骤 / Steps | 预期结果 / Expected Result |
|---------------------|--------------|---------------------------|
| TC1: 从登录页进入后返回 | 1. 打开应用<br>2. 进入登录页<br>3. 点击"忘记密码"<br>4. 点击返回按钮 | 返回到登录页面 |
| TC2: 直接访问 URL 后返回 | 1. 直接访问 `/forgot-password`<br>2. 点击返回按钮 | 导航到 `/login` |
| TC3: 发送邮件后返回 | 1. 进入忘记密码页面<br>2. 输入邮箱并发送<br>3. 点击返回按钮 | 返回到登录页面 |

---

## 📝 实现清单 / Implementation Checklist

### 开发阶段 / Development Phase
- [ ] 修改 `forgot_password_page.dart` 返回按钮逻辑
- [ ] 添加 widget 测试（可选但推荐）
- [ ] 运行现有测试确保无回归
- [ ] 代码格式化和静态分析

### 验证阶段 / Verification Phase
- [ ] 运行 widget 测试: `flutter test test/widget/features/auth/pages/`
- [ ] 运行集成测试: `flutter test test/integration/test_forgot_password_flow.dart`
- [ ] 手动测试所有测试场景
- [ ] 验证 Material Design 规范符合性

### 文档更新 / Documentation Updates
- [x] 创建需求文档（本文档）
- [ ] 实现完成后更新文档状态为 "已完成"

---

## 🚀 部署计划 / Deployment Plan

### 部署前检查 / Pre-deployment Checks
- [ ] 所有测试通过
- [ ] 代码审查完成
- [ ] 手动测试验证
- [ ] 无性能影响

### 部署步骤 / Deployment Steps
1. 合并代码到主分支
2. 触发 CI/CD 流程
3. 发布新版本

---

## 📚 参考资料 / References

- [GoRouter 导航文档](https://pub.dev/packages/go_router)
- [Material Design 导航规范](https://m3.material.io/components/navigation-bar/overview)
- 项目路由配置: `frontend/lib/core/router/app_router.dart`
- 项目 UI/UX 指南: `CLAUDE.md`

---

## 📊 变更历史 / Change History

| 日期 / Date | 版本 / Version | 变更内容 / Changes | 作者 / Author |
|-------------|----------------|-------------------|---------------|
| 2025-12-28 | 1.0 | 初始版本 / Initial version | Claude (Product Manager) |
| | | | |

---

**状态 / Status**: 🟡 进行中 / In Progress
**下一步行动 / Next Action**: 前端工程师开始实现修复
