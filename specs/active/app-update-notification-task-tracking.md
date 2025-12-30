# App Update Notification Feature - Task Tracking / 应用更新提醒功能 - 任务跟踪

**需求ID**: REQ-20251230-001
**功能名称**: App Update Notification Feature / 应用更新提醒功能
**创建日期**: 2025-12-30
**负责人**: Product Manager

---

## 任务总览 / Task Overview

| 任务ID | 任务名称 | 负责人 | 状态 | 预估工时 | 开始日期 | 完成日期 |
|-------|---------|-------|------|---------|---------|---------|
| TASK-F-001 | 创建更新检查服务 | Frontend Dev | Todo | 3h | - | - |
| TASK-F-002 | 创建更新状态管理 | Frontend Dev | Todo | 2h | - | - |
| TASK-F-003 | 创建更新对话框 UI 组件 | Frontend Dev | Todo | 4h | - | - |
| TASK-F-004 | 在设置页面添加检查更新入口 | Frontend Dev | Todo | 2h | - | - |
| TASK-F-005 | 添加应用启动时自动检查 | Frontend Dev | Todo | 2h | - | - |
| TASK-F-006 | 更新 AppConstants 添加 GitHub 配置 | Frontend Dev | Todo | 0.5h | - | - |
| TASK-T-001 | 单元测试 - 更新检查服务 | Test Engineer | Todo | 2h | - | - |
| TASK-T-002 | Widget 测试 - 更新对话框 | Test Engineer | Todo | 2h | - | - |
| TASK-T-003 | 集成测试 - 完整更新流程 | Test Engineer | Todo | 3h | - | - |

**总预估工时**: 20.5 小时

---

## 详细任务列表 / Detailed Task List

### Frontend Tasks

#### TASK-F-001: 创建更新检查服务 / Create Update Check Service
- **负责人**: Frontend Developer
- **状态**: Todo / 待开始
- **优先级**: High
- **预估工时**: 3 小时
- **依赖**: 无
- **文件**:
  - `frontend/lib/core/services/app_update_service.dart`
  - `frontend/lib/shared/models/github_release.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 实现 `GitHubRelease` 数据模型
  - [ ] `fromJson` 工厂方法
  - [ ] `version` getter (移除 'v' 前缀)
- [ ] 实现 `AppUpdateService` 类
  - [ ] `fetchLatestRelease()` 方法：调用 GitHub API
  - [ ] `getCurrentVersion()` 方法：从 package_info_plus 获取
  - [ ] `compareVersions()` 方法：版本号比较
  - [ ] `checkForUpdates()` 主方法：完整检查流程
- [ ] 实现本地缓存（SharedPreferences）
  - [ ] 缓存最新 Release 信息
  - [ ] 缓存检查时间戳
  - [ ] 实现缓存过期逻辑（24小时）
- [ ] 实现错误处理
  - [ ] 网络异常处理
  - [ ] API 限流处理
  - [ ] JSON 解析错误处理
  - [ ] 超时处理（10秒）
- [ ] 添加日志记录（使用 Logger）

**实现要点 / Implementation Notes**:
```dart
class AppUpdateService {
  final Dio _dio;
  final SharedPreferences _prefs;

  Future<GitHubRelease?> fetchLatestRelease();
  Future<String> getCurrentVersion();
  bool compareVersions(String current, String latest);
  Future<UpdateCheckResult> checkForUpdates({bool forceRefresh = false});
}
```

---

#### TASK-F-002: 创建更新状态管理 / Create Update State Management
- **负责人**: Frontend Developer
- **状态**: Todo / 待开始
- **优先级**: High
- **预估工时**: 2 小时
- **依赖**: TASK-F-001
- **文件**:
  - `frontend/lib/features/settings/presentation/providers/app_update_provider.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 定义 `UpdateStatus` 枚举
  - [ ] `initial`, `checking`, `upToDate`, `updateAvailable`, `error`
- [ ] 定义 `UpdateState` 类
  - [ ] 包含 `status`, `latestRelease`, `currentVersion`, `errorMessage`
- [ ] 创建 `UpdateNotifier` 类（继承 `StateNotifier`）
  - [ ] `checkForUpdates()` 方法
  - [ ] `getCurrentVersion()` 方法
  - [ ] 实现错误状态管理
- [ ] 创建 Riverpod Provider
  - [ ] `appUpdateServiceProvider` (单例)
  - [ ] `appUpdateNotifierProvider` (状态)
- [ ] 添加 Provider 测试

**实现要点 / Implementation Notes**:
```dart
final appUpdateServiceProvider = Provider<AppUpdateService>((ref) {
  return AppUpdateService(ref.watch(dioProvider), ref.watch(sharedPrefsProvider));
});

final appUpdateNotifierProvider = StateNotifierProvider<UpdateNotifier, UpdateState>((ref) {
  return UpdateNotifier(ref.watch(appUpdateServiceProvider));
});
```

---

#### TASK-F-003: 创建更新对话框 UI 组件 / Create Update Dialog UI
- **负责人**: Frontend Developer
- **状态**: Todo / 待开始
- **优先级**: High
- **预估工时**: 4 小时
- **依赖**: TASK-F-001, TASK-F-002
- **文件**:
  - `frontend/lib/features/settings/presentation/widgets/update_dialog.dart`

**验收标准 / Acceptance Criteria**:
- [ ] Material 3 设计风格对话框
  - [ ] 使用 `AlertDialog` 组件
  - [ ] 自定义图标（新版本徽章）
  - [ ] 响应式布局（桌面/移动端适配）
- [ ] 双语支持
  - [ ] 中文/英文切换
  - [ ] 使用 `AppLocalizations`
- [ ] UI 元素
  - [ ] 新版本号显示
  - [ ] 当前版本号显示
  - [ ] 更新日志（Markdown 渲染）
  - [ ] "立即更新"按钮（主按钮）
  - [ ] "稍后提醒"按钮（次要按钮）
  - [ ] 可选："跳过此版本"按钮
- [ ] 交互逻辑
  - [ ] 点击"立即更新"调用 `url_launcher` 打开 GitHub Release 页面
  - [ ] 点击"稍后提醒"关闭对话框
  - [ ] 点击"跳过此版本"记录到 SharedPreferences
- [ ] Widget 测试

**实现要点 / Implementation Notes**:
```dart
class UpdateDialog extends StatelessWidget {
  final GitHubRelease release;
  final String currentVersion;

  static Future<void> show(BuildContext context, {
    required GitHubRelease release,
    required String currentVersion,
  });
}
```

---

#### TASK-F-004: 在设置页面添加检查更新入口 / Add Update Entry in Settings
- **负责人**: Frontend Developer
- **状态**: Todo / 待开始
- **优先级**: Medium
- **预估工时**: 2 小时
- **依赖**: TASK-F-002, TASK-F-003
- **文件**:
  - `frontend/lib/features/settings/presentation/pages/settings_page.dart`
  - `frontend/lib/core/localization/app_localizations_en.dart`
  - `frontend/lib/core/localization/app_localizations_zh.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 在"关于"部分添加"检查更新"按钮
  - [ ] 使用 `ListTile` 或 `OutlinedButton`
  - [ ] 显示图标（`system_update` 或 `cloud_download`）
- [ ] 版本号可点击触发检查
  - [ ] 添加点击事件
  - [ ] 显示视觉反馈（Ripple 效果）
- [ ] 动态显示当前版本号
  - [ ] 使用 `package_info_plus` 获取
  - [ ] 不再硬编码版本号
- [ ] 检查时显示加载指示器
  - [ ] 使用 `CircularProgressIndicator`
  - [ ] 禁用检查按钮
- [ ] 检查结果显示
  - [ ] 有更新：显示 `UpdateDialog`
  - [ ] 已是最新：显示 `SnackBar`
  - [ ] 检查失败：显示错误 `SnackBar`
- [ ] 双语文本添加

**实现要点 / Implementation Notes**:
```dart
// Settings Page "About" Section
ListTile(
  title: Text(l10n.version),
  subtitle: Text(_currentVersion),
  trailing: IconButton(
    icon: const Icon(Icons.system_update),
    onPressed: _checkForUpdates,
  ),
  onTap: _checkForUpdates,
),
ListTile(
  title: Text(l10n.checkForUpdates),
  trailing: _isChecking
      ? const SizedBox(
          width: 20,
          height: 20,
          child: CircularProgressIndicator(strokeWidth: 2),
        )
      : const Icon(Icons.cloud_download),
  onTap: _checkForUpdates,
),
```

---

#### TASK-F-005: 添加应用启动时自动检查 / Add Auto Check on Startup
- **负责人**: Frontend Developer
- **状态**: Todo / 待开始
- **优先级**: Medium
- **预估工时**: 2 小时
- **依赖**: TASK-F-002
- **文件**:
  - `frontend/lib/core/app/app.dart` 或 `splash_page.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 应用启动后自动触发更新检查
  - [ ] 在 Splash 页面加载完成后
  - [ ] 在用户登录成功后
- [ ] 检查在后台进行
  - [ ] 不阻塞 UI
  - [ ] 不延迟应用启动
- [ ] 有新版本时的提示方式（三选一）
  - [ ] 选项A：显示 Badge 在设置图标上
  - [ ] 选项B：显示非阻塞式 SnackBar
  - [ ] 选项C：延迟显示对话框（5秒后）
- [ ] 实现频率限制
  - [ ] 最多每天检查一次
  - [ ] 使用 SharedPreferences 记录检查时间
- [ ] 可配置
  - [ ] 添加设置选项："自动检查更新"
  - [ ] 默认启用

**实现要点 / Implementation Notes**:
```dart
// In app.dart or splash_page.dart
void _performStartupChecks() async {
  // Auto check for updates (once per day)
  final prefs = await SharedPreferences.getInstance();
  final lastCheck = prefs.getInt('last_update_check') ?? 0;
  final now = DateTime.now().millisecondsSinceEpoch;
  const oneDay = 24 * 60 * 60 * 1000;

  if (now - lastCheck > oneDay) {
    ref.read(appUpdateNotifierProvider.notifier).checkForUpdates();
    await prefs.setInt('last_update_check', now);
  }
}
```

---

#### TASK-F-006: 更新 AppConstants 添加 GitHub 配置 / Update AppConstants
- **负责人**: Frontend Developer
- **状态**: Todo / 待开始
- **优先级**: High
- **预估工时**: 0.5 小时
- **依赖**: 无
- **文件**:
  - `frontend/lib/core/constants/app_constants.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 添加 GitHub 仓库配置常量
  - [ ] `githubOwner`: 仓库所有者
  - [ ] `githubRepo`: 仓库名称
- [ ] 添加 GitHub API 配置
  - [ ] `githubApiBaseUrl`: API 基础 URL
  - [ ] `githubLatestReleaseUrl`: 最新 Release API 端点
- [ ] 添加更新检查相关常量
  - [ ] `updateCheckCacheDuration`: 缓存时长（24小时）
  - [ ] `updateCheckTimeout`: 请求超时（10秒）
  - [ ] `updateCheckInterval`: 检查间隔（1天）

**实现要点 / Implementation Notes**:
```dart
class AppConstants {
  // ... existing constants

  // GitHub / GitHub 配置
  static const String githubOwner = 'your-org';  // TODO: Replace with actual owner
  static const String githubRepo = 'personal-ai-assistant';
  static const String githubApiBaseUrl = 'https://api.github.com';
  static const String get githubLatestReleaseUrl =>
      '$githubApiBaseUrl/repos/$githubOwner/$githubRepo/releases/latest';

  // App Update / 应用更新
  static const Duration updateCheckCacheDuration = Duration(hours: 24);
  static const Duration updateCheckTimeout = Duration(seconds: 10);
  static const int updateCheckIntervalHours = 24;
}
```

---

### Testing Tasks

#### TASK-T-001: 单元测试 - 更新检查服务 / Unit Tests - Update Service
- **负责人**: Test Engineer
- **状态**: Todo / 待开始
- **优先级**: High
- **预估工时**: 2 小时
- **依赖**: TASK-F-001
- **文件**:
  - `frontend/test/core/services/app_update_service_test.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 测试 GitHub API 调用成功场景
  - [ ] Mock Dio 响应
  - [ ] 验证返回的 `GitHubRelease` 对象
- [ ] 测试网络错误处理
  - [ ] Mock DioException
  - [ ] 验证错误处理逻辑
- [ ] 测试版本号比较逻辑
  - [ ] `1.0.0` vs `0.0.1` → 有更新
  - [ ] `1.0.0` vs `1.0.0` → 无更新
  - [ ] `1.0.0` vs `2.0.0` → 有更新
  - [ ] 测试带 'v' 前缀的版本号
  - [ ] 测试预发布版本号（-alpha, -beta）
- [ ] 测试缓存读写
  - [ ] Mock SharedPreferences
  - [ ] 验证缓存写入
  - [ ] 验证缓存读取
  - [ ] 验证缓存过期逻辑
- [ ] 测试预发布版本过滤
  - [ ] `isPrerelease: true` 的版本过滤
- [ ] 测试覆盖率 > 80%

**实现要点 / Implementation Notes**:
```dart
void main() {
  group('AppUpdateService', () {
    late AppUpdateService service;
    late MockDio mockDio;
    late MockSharedPreferences mockPrefs;

    setUp(() {
      mockDio = MockDio();
      mockPrefs = MockSharedPreferences();
      service = AppUpdateService(mockDio, mockPrefs);
    });

    test('fetchLatestRelease returns GitHubRelease on success', () async {
      // Test implementation
    });

    test('compareVersions correctly compares versions', () {
      expect(service.compareVersions('1.0.0', '0.0.1'), 1);
      expect(service.compareVersions('1.0.0', '1.0.0'), 0);
      expect(service.compareVersions('1.0.0', '2.0.0'), -1);
    });
  });
}
```

---

#### TASK-T-002: Widget 测试 - 更新对话框 / Widget Tests - Update Dialog
- **负责人**: Test Engineer
- **状态**: Todo / 待开始
- **优先级**: High
- **预估工时**: 2 小时
- **依赖**: TASK-F-003
- **文件**:
  - `frontend/test/features/settings/widgets/update_dialog_test.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 测试对话框渲染
  - [ ] 验证对话框显示
  - [ ] 验证版本号文本
  - [ ] 验证按钮存在
- [ ] 测试更新日志显示
  - [ ] 验证 Markdown 内容渲染
  - [ ] 验证长文本滚动
- [ ] 测试"立即更新"按钮点击
  - [ ] Mock `url_launcher`
  - [ ] 验证调用 `launchUrl`
  - [ ] 验证传递正确的 URL
- [ ] 测试"稍后提醒"按钮点击
  - [ ] 验证对话框关闭
  - [ ] 验证 Navigator.pop 调用
- [ ] 测试双语切换
  - [ ] 测试中文环境
  - [ ] 测试英文环境
  - [ ] 验证文本正确性

**实现要点 / Implementation Notes**:
```dart
void main() {
  testWidgets('UpdateDialog displays version information', (tester) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appUpdateNotifierProvider.overrideWith((ref) {
            return MockUpdateNotifier();
          }),
        ],
        child: const MaterialApp(
          home: Scaffold(
            body: UpdateDialog(
              release: mockRelease,
              currentVersion: '0.0.1',
            ),
          ),
        ),
      ),
    );

    expect(find.text('v1.0.0'), findsOneWidget);
    expect(find.text('v0.0.1'), findsOneWidget);
  });

  testWidgets('UpdateDialog launches URL on update button tap', (tester) async {
    // Test implementation
  });
}
```

---

#### TASK-T-003: 集成测试 - 完整更新流程 / Integration Tests - Complete Flow
- **负责人**: Test Engineer
- **状态**: Todo / 待开始
- **优先级**: Medium
- **预估工时**: 3 小时
- **依赖**: TASK-F-005
- **文件**:
  - `frontend/integration_test/app_update_test.dart`

**验收标准 / Acceptance Criteria**:
- [ ] 测试应用启动自动检查
  - [ ] 启动应用
  - [ ] 验证后台调用更新检查
  - [ ] 验证状态更新
- [ ] 测试手动触发检查
  - [ ] 进入设置页面
  - [ ] 点击"检查更新"
  - [ ] 验证加载指示器
  - [ ] 验证结果显示
- [ ] 测试更新对话框显示
  - [ ] 模拟有新版本
  - [ ] 验证对话框弹出
  - [ ] 验证内容正确
- [ ] 测试跳转 GitHub Release 页面
  - [ ] 点击"立即更新"
  - [ ] 验证浏览器打开
  - [ ] 验证 URL 正确
- [ ] 测试"已是最新"提示
  - [ ] 模拟无新版本
  - [ ] 验证 SnackBar 显示
- [ ] 测试网络错误场景
  - [ ] Mock 网络错误
  - [ ] 验证错误提示显示
  - [ ] 验证应用不崩溃

**实现要点 / Implementation Notes**:
```dart
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Complete update flow: check and show dialog', (tester) async {
    await tester.pumpWidget(MyApp());

    // Trigger update check
    await tester.tap(find.text('检查更新'));
    await tester.pumpAndSettle();

    // Verify dialog appears
    expect(find.byType(UpdateDialog), findsOneWidget);
    expect(find.text('v1.0.0'), findsOneWidget);
  });

  testWidgets('Update flow: no update available', (tester) async {
    // Test implementation
  });
}
```

---

## 进度跟踪 / Progress Tracking

### 里程碑状态 / Milestone Status

| 里程碑 / Milestone | 目标日期 / Target | 状态 / Status | 完成日期 / Completed |
|------------------|-----------------|-------------|-------------------|
| 需求确认 | 2025-12-30 | ✅ Completed | 2025-12-30 |
| 设计完成 | 2025-12-30 | ✅ Completed | 2025-12-30 |
| 开发完成 | 2026-01-02 | Todo | - |
| 测试完成 | 2026-01-03 | Todo | - |
| 上线发布 | 2026-01-05 | Todo | - |

### 任务完成率 / Task Completion Rate
- **总任务数**: 9
- **已完成**: 0
- **进行中**: 0
- **待开始**: 9
- **完成率**: 0%

### 阻塞问题 / Blockers
- 无当前阻塞问题

---

## 风险跟踪 / Risk Tracking

| 风险 / Risk | 状态 / Status | 缓解措施 / Mitigation | 负责人 / Owner |
|------------|--------------|---------------------|---------------|
| GitHub API 限流 | 监控中 | 实现缓存，最多每小时检查一次 | Frontend Dev |
| url_launcher Web 兼容性 | 已识别 | Web 平台跳过更新检查 | Frontend Dev |
| 版本号解析边界情况 | 已识别 | 添加全面测试覆盖 | Test Engineer |

---

## 每日更新 / Daily Updates

### 2025-12-30 (Day 1)
- **状态**: 需求创建完成
- **完成**:
  - 创建需求文档 (`app-update-notification-feature.md`)
  - 创建任务跟踪文档 (`app-update-notification-task-tracking.md`)
- **下一步**: 开始执行 TASK-F-006（AppConstants 配置）

### 2025-12-31 (Day 2)
- **状态**: 待开始
- **计划**:
  - 完成 TASK-F-006: AppConstants 配置
  - 开始 TASK-F-001: 更新检查服务
- **预计完成**: TASK-F-006, TASK-F-001 (50%)

---

## 相关文档 / Related Documents

- [需求文档](./app-update-notification-feature.md)
- [产品驱动开发流程](../templates/requirement-template.md)
- [前端架构规范](../../../docs/frontend-architecture.md)

---

**注意 / Note**: 请在每次完成一个任务后更新此文档，保持任务状态的实时同步。
