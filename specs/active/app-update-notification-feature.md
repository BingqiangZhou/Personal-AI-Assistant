# App Update Notification Feature / 应用更新提醒功能

## 基本信息 / Basic Information
- **需求ID**: REQ-20251230-001
- **创建日期**: 2025-12-30
- **最后更新**: 2025-12-30
- **负责人**: Product Manager
- **状态**: Active / 进行中
- **优先级**: Medium / 中等

---

## 需求描述 / Requirement Description

### 用户故事 / User Story

**中文**：
作为 Personal AI Assistant 的用户，我希望在应用启动时能够自动检测是否有新版本可用，如果有新版本，我希望看到清晰的更新提示，包括版本号、更新内容，并能够直接跳转到 GitHub 下载页面，以便我能够及时获取最新功能和 bug 修复。

**English**:
As a user of Personal AI Assistant, I want the app to automatically check for updates when it starts. If a new version is available, I want to see a clear update notification including the version number, changelog, and a direct link to the GitHub download page, so I can quickly get the latest features and bug fixes.

### 业务价值 / Business Value

1. **提升用户体验 / Improve User Experience**
   - 用户能够及时了解新功能和改进
   - 减少因使用旧版本导致的问题

2. **增强用户参与度 / Increase User Engagement**
   - 引导用户升级到最新版本
   - 提高新功能的采用率

3. **减少技术支持成本 / Reduce Support Costs**
   - 减少因旧版本 bug 产生的问题
   - 确保用户使用稳定版本

4. **成功指标 / Success Metrics**
   - 更新检测成功率 > 99%
   - 用户点击"更新"按钮转化率 > 30%
   - 检测响应时间 < 2 秒

### 背景信息 / Background Information

**当前状况 / Current Situation**:
- 应用当前版本：`0.0.1+1` (pubspec.yaml)
- 版本显示在设置页面 (SettingsPage)，硬编码为 `1.0.0`
- 项目已配置 GitHub Actions 自动发布到 Releases
- 支持多平台构建：Android, Windows, Linux, macOS, iOS

**用户痛点 / User Pain Points**:
1. 用户无法知道是否有新版本发布
2. 需要手动检查 GitHub Releases 才能获取更新
3. 缺少引导用户升级的机制

**机会点 / Opportunities**:
1. 利用 GitHub Releases API 获取最新版本信息
2. 在应用启动或设置页面提供版本检查入口
3. 展示更新内容（changelog），吸引用户升级

---

## 功能需求 / Functional Requirements

### 核心功能 / Core Features

- [FR-001] **版本检查功能** - 从 GitHub Releases API 获取最新版本信息
- [FR-002] **版本比较逻辑** - 比较当前版本与最新版本号
- [FR-003] **更新提示对话框** - Material 3 设计风格的双语更新提示 UI
- [FR-004] **跳转下载** - 使用 url_launcher 打开 GitHub Release 页面
- [FR-005] **检查触发机制** - 应用启动时自动检查 + 手动检查入口
- [FR-006] **本地缓存** - 缓存检查结果，避免频繁请求 API

### 功能详述 / Feature Details

#### 功能1：版本检查服务 / Version Check Service
**描述 / Description**:
通过 GitHub Releases API 获取最新发布的版本信息

**输入 / Input**:
- GitHub 仓库信息（owner, repo）
- 当前应用版本号

**处理 / Processing**:
1. 调用 GitHub Releases API: `https://api.github.com/repos/{owner}/{repo}/releases/latest`
2. 解析响应获取：
   - `tag_name`: 最新版本号（如 `v1.0.0`）
   - `name`: Release 名称
   - `body`: 更新日志（Markdown 格式）
   - `html_url`: Release 页面 URL
3. 错误处理：
   - 网络错误：显示友好提示，不影响应用使用
   - API 限流：缓存上一次结果
   - 解析错误：降级处理

**输出 / Output**:
```dart
class GitHubRelease {
  final String tagName;        // v1.0.0
  final String name;           // Release v1.0.0
  final String? body;          // 更新日志
  final String htmlUrl;        // https://github.com/.../releases/tag/v1.0.0
  final bool isPrerelease;     // 是否为预发布版本
  final DateTime publishedAt;  // 发布时间
}
```

#### 功能2：版本比较逻辑 / Version Comparison Logic
**描述 / Description**:
比较当前应用版本与 GitHub 最新版本，判断是否需要更新

**处理逻辑 / Processing Logic**:
1. 从 `pubspec.yaml` 读取当前版本：`version: 0.0.1+1`
   - `version`: `0.0.1` (语义化版本号)
   - `build_number`: `1`
2. 将 GitHub `tag_name` (如 `v1.0.0`) 转换为可比较格式
3. 语义化版本比较：`major.minor.patch`
4. 判断规则：
   - `latest > current` → 显示更新提示
   - `latest <= current` → 已是最新版本
5. 可选配置：是否提示预发布版本 (alpha, beta, rc)

**版本号格式 / Version Format**:
```
pubspec.yaml: version: 0.0.1+1
GitHub tag:  v1.0.0, v0.1.0-beta, v2.0.0-rc.1
```

#### 功能3：更新提示对话框 / Update Notification Dialog
**描述 / Description**:
Material 3 设计风格的双语对话框，显示新版本信息

**UI 设计 / UI Design**:
```
┌─────────────────────────────────────────┐
│ 🎉 新版本可用！    ┌──────┐  ┌────┐   │
│                   │关闭  │  │更新│   │
├─────────────────────────────────────────┤
│                                         │
│  发现新版本 v1.0.0                       │
│  当前版本: v0.0.1                        │
│                                         │
│  ┌─────────────────────────────────┐   │
│  │ 📦 更新内容 / What's New:       │   │
│  │                                 │   │
│  │ • 新功能: 播客音频转录          │   │
│  │ • 优化: 播放器性能提升          │   │
│  │ • 修复: 修复登录问题            │   │
│  │                                 │   │
│  └─────────────────────────────────┘   │
│                                         │
│  [稍后提醒我 / Remind Me Later]         │
│  [立即更新 / Update Now]                │
│                                         │
└─────────────────────────────────────────┘
```

**交互行为 / Interaction**:
- **立即更新 / Update Now**:
  - 使用 `url_launcher` 打开 GitHub Release 页面
  - 用户可下载对应平台的安装包
- **稍后提醒 / Remind Me Later**:
  - 关闭对话框
  - 记录"已提示"状态，下次启动不再重复提示
- **跳过此版本 / Skip This Version** (可选):
  - 记录跳过的版本号
  - 只有更高版本才再次提示

#### 功能4：手动检查入口 / Manual Check Trigger
**描述 / Description**:
在设置页面提供"检查更新"按钮

**位置 / Location**:
```
设置页面 (Settings Page)
└── About / 关于
    ├── 版本: 1.0.0 (点击可检查更新)
    ├── 检查更新按钮
    └── 后端 API 文档
```

**交互流程 / Interaction Flow**:
1. 用户点击"检查更新"或版本号
2. 显示加载指示器
3. 检查完成：
   - **有新版本**: 显示更新对话框
   - **已是最新**: 显示 Toast 提示 "已是最新版本 / You're up to date"
   - **检查失败**: 显示错误提示

#### 功能5：自动检查机制 / Auto Check on Startup
**描述 / Description**:
应用启动时自动检查更新（静默检查）

**触发时机 / Trigger Timing**:
1. 应用冷启动（Splash 页面后）
2. 用户登录成功后
3. 频率限制：最多每天检查一次（使用本地缓存）

**静默检查流程 / Silent Check Flow**:
1. 后台调用 GitHub API（不阻塞 UI）
2. 如果有新版本：
   - 显示小红点或 Badge 在设置页面
   - 或显示非阻塞式通知（SnackBar）
3. 记录检查时间和结果

---

## 非功能需求 / Non-Functional Requirements

### 性能要求 / Performance Requirements
- **API 响应时间**: < 2 秒（首次检查，有缓存时 < 100ms）
- **UI 渲染延迟**: < 300ms（对话框显示）
- **内存占用**: < 5 MB（更新检查服务）
- **网络流量**: < 50 KB/次（API 响应 + changelog）

### 安全要求 / Security Requirements
- **HTTPS**: 所有网络请求使用 HTTPS
- **API 限流**: 遵守 GitHub API 限流（60 次/小时，未认证）
- **数据验证**: 验证 API 响应数据格式
- **隐私保护**: 不收集用户信息，仅检查更新

### 可用性要求 / Usability Requirements
- **离线降级**: 网络不可用时，显示缓存的最后检查结果
- **错误友好**: 网络错误时显示友好提示，不影响应用使用
- **可配置**: 用户可以在设置中禁用自动检查
- **多语言**: 支持中文和英文双语界面

### 兼容性要求 / Compatibility Requirements
- **Flutter 版本**: >= 3.8.0
- **平台支持**:
  - Android: API 21+
  - iOS: 12.0+
  - Windows: Windows 10+
  - macOS: 10.14+
  - Linux: 主流发行版
- **Dart 版本**: >= 3.8.0

---

## 技术需求 / Technical Requirements

### 技术栈 / Technology Stack
- **HTTP Client**: Dio (已有依赖)
- **本地存储**: SharedPreferences (已有依赖)
- **URL 跳转**: url_launcher (已有依赖)
- **状态管理**: Riverpod (已有依赖)
- **国际化**: 自定义双语支持

### 新增依赖 / New Dependencies
**无需新增依赖**，使用现有依赖：
```yaml
# 已有依赖
dio: ^5.5.0                    # HTTP 请求
shared_preferences: ^2.2.2     # 本地缓存
url_launcher: ^6.3.2           # 打开 GitHub 链接
flutter_riverpod: ^3.0.3       # 状态管理
package_info_plus: ^9.0.0      # 获取应用版本信息
```

### 架构设计 / Architecture Design

#### 代码结构 / Code Structure
```
frontend/lib/
├── core/
│   ├── constants/
│   │   └── app_constants.dart       # 添加 GitHub 仓库常量
│   └── services/
│       └── app_update_service.dart  # 更新检查服务
├── features/
│   └── settings/
│       ├── presentation/
│       │   ├── providers/
│       │   │   └── app_update_provider.dart  # 更新状态管理
│       │   ├── widgets/
│       │   │   └── update_dialog.dart         # 更新对话框组件
│       │   └── pages/
│       │       └── settings_page.dart         # 添加"检查更新"入口
└── shared/
    └── models/
        └── github_release.dart      # GitHub Release 数据模型
```

#### API 接口 / API Endpoint
```
GET https://api.github.com/repos/{owner}/{repo}/releases/latest

响应示例:
{
  "tag_name": "v1.0.0",
  "name": "Release v1.0.0",
  "body": "## 📦 Release v1.0.0\n\n- 新功能: ...",
  "html_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
  "prerelease": false,
  "published_at": "2025-12-30T00:00:00Z"
}
```

### 数据模型 / Data Models

```dart
// lib/shared/models/github_release.dart
class GitHubRelease {
  final String tagName;
  final String name;
  final String? body;
  final String htmlUrl;
  final bool isPrerelease;
  final DateTime publishedAt;

  GitHubRelease({
    required this.tagName,
    required this.name,
    this.body,
    required this.htmlUrl,
    required this.isPrerelease,
    required this.publishedAt,
  });

  // 解析版本号 (移除 'v' 前缀)
  String get version => tagName.replaceFirst('v', '');

  // 从 JSON 创建
  factory GitHubRelease.fromJson(Map<String, dynamic> json) {
    return GitHubRelease(
      tagName: json['tag_name'] ?? '',
      name: json['name'] ?? '',
      body: json['body'],
      htmlUrl: json['html_url'] ?? '',
      isPrerelease: json['prerelease'] ?? false,
      publishedAt: DateTime.parse(json['published_at']),
    );
  }
}

// 更新检查状态
enum UpdateStatus {
  initial,      // 初始状态
  checking,     // 检查中
  upToDate,     // 已是最新
  updateAvailable,  // 有新版本
  error,        // 检查失败
}

class UpdateState {
  final UpdateStatus status;
  final GitHubRelease? latestRelease;
  final String? currentVersion;
  final String? errorMessage;

  UpdateState({
    required this.status,
    this.latestRelease,
    this.currentVersion,
    this.errorMessage,
  });
}
```

---

## 任务分解 / Task Breakdown

### Frontend任务 / Frontend Tasks

#### TASK-F-001: 创建更新检查服务
- **负责人**: Frontend Developer
- **预估工时**: 3 小时
- **文件**:
  - `frontend/lib/core/services/app_update_service.dart`
  - `frontend/lib/shared/models/github_release.dart`
- **验收标准**:
  - [ ] 实现获取 GitHub Releases API 的方法
  - [ ] 实现版本号比较逻辑
  - [ ] 实现本地缓存（SharedPreferences）
  - [ ] 实现网络错误处理和降级
  - [ ] 单元测试覆盖率 > 80%
- **依赖**: 无
- **状态**: Todo

#### TASK-F-002: 创建更新状态管理 (Riverpod Provider)
- **负责人**: Frontend Developer
- **预估工时**: 2 小时
- **文件**:
  - `frontend/lib/features/settings/presentation/providers/app_update_provider.dart`
- **验收标准**:
  - [ ] 创建 `UpdateNotifier` 类管理更新状态
  - [ ] 实现 `checkForUpdates()` 方法
  - [ ] 实现自动检查（应用启动时）
  - [ ] 实现手动检查（用户触发）
  - [ ] Provider 测试通过
- **依赖**: TASK-F-001
- **状态**: Todo

#### TASK-F-003: 创建更新对话框 UI 组件
- **负责人**: Frontend Developer
- **预估工时**: 4 小时
- **文件**:
  - `frontend/lib/features/settings/presentation/widgets/update_dialog.dart`
- **验收标准**:
  - [ ] Material 3 设计风格对话框
  - [ ] 双语支持（中文/英文）
  - [ ] 显示版本号和更新日志
  - [ ] "立即更新"按钮使用 url_launcher 跳转
  - [ ] "稍后提醒"按钮关闭对话框
  - [ ] 响应式设计（桌面/移动端适配）
  - [ ] Widget 测试通过
- **依赖**: TASK-F-001, TASK-F-002
- **状态**: Todo

#### TASK-F-004: 在设置页面添加检查更新入口
- **负责人**: Frontend Developer
- **预估工时**: 2 小时
- **文件**:
  - `frontend/lib/features/settings/presentation/pages/settings_page.dart`
  - `frontend/lib/core/localization/app_localizations_en.dart` (添加翻译)
  - `frontend/lib/core/localization/app_localizations_zh.dart` (添加翻译)
- **验收标准**:
  - [ ] 在"关于"部分添加"检查更新"按钮
  - [ ] 版本号可点击触发检查
  - [ ] 显示当前版本号（从 package_info_plus 动态获取）
  - [ ] 检查时显示加载指示器
  - [ ] 检查结果显示 Toast 或对话框
  - [ ] 双语文本添加
- **依赖**: TASK-F-002, TASK-F-003
- **状态**: Todo

#### TASK-F-005: 添加应用启动时自动检查
- **负责人**: Frontend Developer
- **预估工时**: 2 小时
- **文件**:
  - `frontend/lib/core/app/app.dart` 或 `splash_page.dart`
- **验收标准**:
  - [ ] 应用启动后自动触发更新检查
  - [ ] 检查在后台进行，不阻塞 UI
  - [ ] 有新版本时显示非阻塞式提示
  - [ ] 实现频率限制（每天最多一次）
  - [ ] 可配置（用户可禁用）
- **依赖**: TASK-F-002
- **状态**: Todo

#### TASK-F-006: 更新 AppConstants 添加 GitHub 配置
- **负责人**: Frontend Developer
- **预估工时**: 0.5 小时
- **文件**:
  - `frontend/lib/core/constants/app_constants.dart`
- **验收标准**:
  - [ ] 添加 GitHub 仓库配置常量
  - [ ] 添加 GitHub API URL 常量
  - [ ] 添加缓存相关常量
- **依赖**: 无
- **状态**: Todo

### 测试任务 / Testing Tasks

#### TASK-T-001: 单元测试 - 更新检查服务
- **负责人**: Test Engineer
- **预估工时**: 2 小时
- **文件**:
  - `frontend/test/core/services/app_update_service_test.dart`
- **验收标准**:
  - [ ] 测试 GitHub API 调用成功场景
  - [ ] 测试网络错误处理
  - [ ] 测试版本号比较逻辑（各种边界情况）
  - [ ] 测试缓存读写
  - [ ] 测试预发布版本过滤
  - [ ] Mock GitHub API 响应
- **依赖**: TASK-F-001
- **状态**: Todo

#### TASK-T-002: Widget 测试 - 更新对话框
- **负责人**: Test Engineer
- **预估工时**: 2 小时
- **文件**:
  - `frontend/test/features/settings/widgets/update_dialog_test.dart`
- **验收标准**:
  - [ ] 测试对话框渲染
  - [ ] 测试版本号显示
  - [ ] 测试更新日志显示
  - [ ] 测试"立即更新"按钮点击
  - [ ] 测试"稍后提醒"按钮点击
  - [ ] 测试双语切换
- **依赖**: TASK-F-003
- **状态**: Todo

#### TASK-T-003: 集成测试 - 完整更新流程
- **负责人**: Test Engineer
- **预估工时**: 3 小时
- **文件**:
  - `frontend/integration_test/app_update_test.dart`
- **验收标准**:
  - [ ] 测试应用启动自动检查
  - [ ] 测试手动触发检查
  - [ ] 测试更新对话框显示
  - [ ] 测试跳转 GitHub Release 页面
  - [ ] 测试"已是最新"提示
  - [ ] 测试网络错误场景
- **依赖**: TASK-F-005
- **状态**: Todo

---

## 验收标准 / Acceptance Criteria

### 整体验收 / Overall Acceptance
- [ ] 所有功能需求已实现
- [ ] 所有平台测试通过（Android, iOS, Windows, macOS, Linux）
- [ ] 双语支持验证通过（中文/英文）
- [ ] 性能指标达标
- [ ] 代码质量达标

### 用户验收标准 / User Acceptance Criteria

#### 场景1：应用有新版本可用
- [ ] 用户启动应用，自动检查更新
- [ ] 发现有新版本 v1.0.0（当前 v0.0.1）
- [ ] 显示更新提示对话框
- [ ] 对话框显示：
  - [ ] 新版本号 v1.0.0
  - [ ] 当前版本号 v0.0.1
  - [ ] 更新内容（changelog）
- [ ] 点击"立即更新"，跳转到 GitHub Release 页面
- [ ] 浏览器打开正确的 Release 页面

#### 场景2：手动检查更新（有新版本）
- [ ] 用户进入设置页面
- [ ] 点击"检查更新"按钮
- [ ] 显示加载指示器
- [ ] 检查完成，显示更新对话框
- [ ] 对话框内容正确显示

#### 场景3：手动检查更新（已是最新）
- [ ] 用户进入设置页面
- [ ] 点击"检查更新"按钮
- [ ] 检查完成，显示 Toast: "已是最新版本 / You're up to date"
- [ ] 不显示更新对话框

#### 场景4：网络错误
- [ ] 用户点击"检查更新"
- [ ] 网络不可用或 GitHub API 超时
- [ ] 显示友好错误提示: "检查更新失败，请稍后重试"
- [ ] 应用其他功能不受影响

#### 场景5：双语支持
- [ ] 系统语言为中文，对话框显示中文
- [ ] 系统语言为英文，对话框显示英文
- [ ] 所有文本正确翻译

#### 场景6：缓存和频率限制
- [ ] 首次检查，调用 GitHub API
- [ ] 再次检查（1分钟内），使用缓存，不调用 API
- [ ] 应用启动自动检查，最多每天一次

### 技术验收标准 / Technical Acceptance Criteria

#### 代码质量
- [ ] 代码遵循 `flutter_lints` 和 `very_good_analysis` 规范
- [ ] 所有 `public` API 添加文档注释
- [ ] 没有硬编码的字符串（使用本地化）
- [ ] 错误处理完整，没有未捕获的异常

#### 测试覆盖率
- [ ] 单元测试覆盖率 > 80%
- [ ] 所有 Widget 测试通过
- [ ] 集成测试覆盖主要场景
- [ ] 没有 `print` 语句调试代码（使用 logger）

#### 性能验证
- [ ] 更新检查 API 响应时间 < 2 秒
- [ ] 对话框渲染延迟 < 300ms
- [ ] 内存占用增加 < 5 MB
- [ ] 没有内存泄漏

#### 兼容性验证
- [ ] Android 测试通过（API 21+）
- [ ] iOS 测试通过（12.0+）
- [ ] Windows 测试通过
- [ ] macOS 测试通过
- [ ] Linux 测试通过
- [ ] Web 平台降级处理（跳过更新检查）

---

## 设计约束 / Design Constraints

### 技术约束 / Technical Constraints
- **必须使用** Dio 进行 HTTP 请求（已有依赖）
- **必须使用** Riverpod 进行状态管理（已有架构）
- **必须遵循** Material 3 设计规范
- **必须支持** 双语（中文/英文）
- **不能添加** 新的大型依赖（使用现有依赖）

### 业务约束 / Business Constraints
- **GitHub API 限流**: 未认证 60 次/小时，需要实现缓存
- **版本号格式**: 必须遵循语义化版本 (Semantic Versioning)
- **预发布版本**: 可选配置是否提示 alpha/beta/rc 版本

### 环境约束 / Environmental Constraints
- **Web 平台**: url_launcher 在 Web 端行为不同，需要特殊处理
- **移动端**: 需要处理应用内浏览器 vs 系统浏览器选择
- **网络**: 需要处理弱网环境下的超时和重试

---

## 风险评估 / Risk Assessment

### 技术风险 / Technical Risks

| 风险项 / Risk | 概率 / Probability | 影响 / Impact | 缓解措施 / Mitigation |
|--------------|-------------------|--------------|---------------------|
| GitHub API 限流 | 中 | 中 | 实现缓存，最多每小时检查一次；使用 ETag |
| 网络超时或失败 | 高 | 低 | 添加超时重试；离线时显示缓存结果 |
| 版本号解析错误 | 低 | 高 | 严格测试各种版本号格式；添加异常捕获 |
| url_launcher 在 Web 端不工作 | 中 | 低 | Web 平台跳过更新检查功能 |
| 用户禁用自动更新 | 中 | 低 | 提供设置选项，默认启用 |

### 业务风险 / Business Risks

| 风险项 / Risk | 概率 / Probability | 影响 / Impact | 缓解措施 / Mitigation |
|--------------|-------------------|--------------|---------------------|
| 用户觉得更新提示太频繁 | 中 | 中 | 实现"跳过此版本"功能；最多每天提示一次 |
| 更新对话框设计不够吸引 | 低 | 低 | 参考 Material 3 设计规范；A/B 测试 |
| GitHub Release 内容不完整 | 中 | 低 | 降级处理，显示默认更新提示 |

---

## 依赖关系 / Dependencies

### 外部依赖 / External Dependencies
- **GitHub Releases API** - 获取最新版本信息 - 可用性 99.9%
- **GitHub Releases Page** - 用户下载更新的页面 - 依赖 GitHub 服务可用性

### 内部依赖 / Internal Dependencies
- **package_info_plus** - 获取当前应用版本号 - 已有依赖
- **url_launcher** - 打开 GitHub Release 页面 - 已有依赖
- **shared_preferences** - 缓存检查结果 - 已有依赖
- **Dio** - HTTP 请求客户端 - 已有依赖
- **Riverpod** - 状态管理 - 已有架构
- **双语系统** - 本地化支持 - 已有框架

---

## 时间线 / Timeline

### 里程碑 / Milestones

| 里程碑 / Milestone | 目标日期 / Target Date | 交付物 / Deliverables |
|-------------------|----------------------|---------------------|
| 需求确认 | 2025-12-30 | 需求文档完成并审批 |
| 设计完成 | 2025-12-30 | 数据模型、API 设计完成 |
| 开发完成 | 2026-01-02 | 所有代码实现完成 |
| 测试完成 | 2026-01-03 | 所有测试通过 |
| 上线发布 | 2026-01-05 | 功能发布到生产环境 |

### 关键路径 / Critical Path
```
需求确认 (0.5天)
  ↓
TASK-F-006: AppConstants 配置 (0.5天)
  ↓
TASK-F-001: 更新检查服务 (3天)
  ↓
TASK-F-002: Riverpod Provider (2天)
  ├→ TASK-F-005: 自动检查 (2天)
  └→ TASK-F-003: 对话框 UI (4天)
      ↓
      TASK-F-004: 设置页面集成 (2天)
      ↓
      测试 (2天)
```

**总工期**: 约 8 个工作日

---

## 变更记录 / Change Log

| 版本 / Version | 日期 / Date | 变更内容 / Changes | 变更人 / Author | 审批人 / Reviewer |
|---------------|------------|------------------|----------------|------------------|
| 1.0 | 2025-12-30 | 初始需求创建 | Product Manager | - |

---

## 相关文档 / Related Documents

- [产品驱动开发流程](../templates/requirement-template.md)
- [GitHub Releases API 文档](https://docs.github.com/en/rest/releases/releases#get-the-latest-release)
- [package_info_plus 文档](https://pub.dev/packages/package_info_plus)
- [url_launcher 文档](https://pub.dev/packages/url_launcher)
- [Material 3 对话框指南](https://m3.material.io/components/dialogs/overview)

---

## 审批 / Approval

### 需求评审 / Requirement Review
- [x] 产品经理审批 / Product Manager Approval
- [ ] 技术负责人审批 / Tech Lead Approval
- [ ] QA负责人审批 / QA Lead Approval

### 上线审批 / Release Approval
- [ ] 产品负责人 / Product Owner
- [ ] 技术负责人 / Tech Lead
- [ ] 运维负责人 / DevOps Lead

---

## 附录 / Appendix

### A. 版本号比较算法
```dart
/// 比较两个语义化版本号
/// 返回值: 1 (v1 > v2), -1 (v1 < v2), 0 (v1 == v2)
int compareVersions(String v1, String v2) {
  // 移除 'v' 前缀
  v1 = v1.replaceFirst('v', '');
  v2 = v2.replaceFirst('v', '');

  // 移除预发布标识符 (-alpha, -beta, -rc)
  final v1Main = v1.split('-')[0];
  final v2Main = v2.split('-')[0];

  final parts1 = v1Main.split('.').map(int.parse).toList();
  final parts2 = v2Main.split('.').map(int.parse).toList();

  // 比较 major.minor.patch
  for (int i = 0; i < 3; i++) {
    final p1 = i < parts1.length ? parts1[i] : 0;
    final p2 = i < parts2.length ? parts2[i] : 0;
    if (p1 > p2) return 1;
    if (p1 < p2) return -1;
  }

  return 0; // 版本相同
}
```

### B. GitHub 仓库配置
```dart
// frontend/lib/core/constants/app_constants.dart
class AppConstants {
  // ... 现有常量

  // App Update / 应用更新
  static const String githubOwner = 'your-org';  // 替换为实际仓库所有者
  static const String githubRepo = 'personal-ai-assistant';
  static const String githubApiBaseUrl = 'https://api.github.com';
  static const Duration updateCheckCacheDuration = Duration(hours: 24);
  static const Duration updateCheckTimeout = Duration(seconds: 10);
}
```

### C. 本地化文本 / Localization Strings
```dart
// app_localizations_en.dart
abstract class AppLocalizations {
  // ... 现有翻译

  // App Update / 应用更新
  String get updateAvailable;
  String get newVersionAvailable;
  String get currentVersion;
  String get whatsNew;
  String get updateNow;
  String get remindMeLater;
  String get skipThisVersion;
  String get checkForUpdates;
  String get checkingForUpdates;
  String get alreadyUpToDate;
  String get updateCheckFailed;
  String get updateCheckError;
}

// app_localizations_zh.dart
abstract class AppLocalizations {
  // ... 现有翻译

  // App Update / 应用更新
  String get updateAvailable;  // "新版本可用！"
  String get newVersionAvailable;  // "发现新版本"
  String get currentVersion;  // "当前版本"
  String get whatsNew;  // "更新内容"
  String get updateNow;  // "立即更新"
  String get remindMeLater;  // "稍后提醒"
  String get skipThisVersion;  // "跳过此版本"
  String get checkForUpdates;  // "检查更新"
  String get checkingForUpdates;  // "正在检查更新..."
  String get alreadyUpToDate;  // "已是最新版本"
  String get updateCheckFailed;  // "检查更新失败"
  String get updateCheckError;  // "网络错误，请稍后重试"
}
```

---

**注意 / Note**: 本文档是应用更新提醒功能的核心需求文档，请遵循产品驱动开发流程严格执行。所有功能实现必须先经过架构评审和技术设计。
