# 服务器地址设置功能增强 / Server Address Settings Enhancement

**需求编号 / PRD ID**: PRD-2025-001
**创建日期 / Created**: 2025-12-30
**完成日期 / Completed**: 2025-12-30
**优先级 / Priority**: P1 (高)
**状态 / Status**: ✅ Completed / 已完成

---

## 📄 需求概述 / Overview

### 中文描述
在设置页面最上方添加服务器地址设置功能，让用户可以方便地配置后端服务器地址。同时在登录页面添加服务器地址设置入口（长按应用图标触发）。两个设置界面都提供"恢复默认"按钮，允许用户快速重置为默认服务器地址。使用共享的 `ServerConfigDialog` 组件确保一致的用户体验。

### English Description
Add a server address configuration feature at the top of the settings page, allowing users to conveniently configure the backend server address. Additionally, add a server address settings entry on the login page (triggered by long-pressing the app icon). Both settings interfaces provide a "Restore Defaults" button to allow users to quickly reset to the default server address. Uses the shared `ServerConfigDialog` component to ensure consistent user experience.

---

## 🎯 用户故事 / User Stories

### US-001: Settings Page Server Configuration
**作为 / As** 一个用户
**我想要 / I want** 在设置页面最上方直接配置服务器地址
**以便 / So that** 我可以方便地更改后端服务器而无需通过隐藏功能

**验收标准 / Acceptance Criteria:**
- [x] 设置页面最上方显示"服务器配置"部分
- [x] 显示当前服务器地址
- [x] 显示连接状态指示器
- [x] 提供"配置"按钮打开对话框
- [x] 对话框包含服务器地址输入框
- [x] 对话框包含"测试连接"功能（实时验证）
- [x] 对话框包含"保存"按钮
- [x] 对话框包含"恢复默认"按钮
- [x] 支持本地地址快捷按钮（"本地"按钮）
- [x] 实时显示连接状态和响应时间

### US-002: Login Page Server Configuration
**作为 / As** 一个用户
**我想要 / I want** 在登录页面能够设置服务器地址
**以便 / So that** 我可以在首次使用或连接失败时配置正确的服务器

**验收标准 / Acceptance Criteria:**
- [x] 登录页面应用图标支持长按触发服务器设置
- [x] 长按后弹出服务器设置对话框
- [x] 对话框包含所有必需的设置选项
- [x] 对话框包含"恢复默认"按钮
- [x] 对话框与设置页面使用相同的共享组件
- [x] 设置完成后URL地址正确用于访问后台

### US-003: Restore Defaults Functionality
**作为 / As** 一个用户
**我想要 / I want** 通过"恢复默认"按钮快速重置服务器地址
**以便 / So that** 我可以在配置错误时快速恢复到默认状态

**验收标准 / Acceptance Criteria:**
- [x] "恢复默认"按钮点击后重置为环境默认地址
- [x] 重置前显示确认对话框
- [x] 重置后自动测试新连接
- [x] 显示重置成功的提示信息

---

## ✅ 实现总结 / Implementation Summary

### 实现的功能 / Implemented Features

1. **设置页面服务器配置**
   - 在设置页面最上方添加了服务器配置卡片
   - 显示当前服务器地址和连接状态
   - 点击"配置"按钮打开服务器配置对话框

2. **共享的服务器配置对话框** (`lib/shared/widgets/server_config_dialog.dart`)
   - 统一的服务器配置界面
   - 支持设置页面和登录页面复用
   - 包含服务器地址输入框
   - 实时连接验证（500ms 防抖）
   - "本地"快捷按钮（填入 localhost:8000）
   - "恢复默认"按钮（带确认对话框）
   - "保存"按钮（仅在连接成功时可用）

3. **登录页面服务器设置**
   - 长按应用图标触发服务器配置对话框
   - 使用相同的共享 `ServerConfigDialog` 组件

4. **本地化支持**
   - 新增本地化字符串：
     - `restore_defaults`: "恢复默认" / "Restore Defaults"
     - `restore_defaults_confirmation`: 确认消息
     - `restore_defaults_success`: 成功消息
     - `default_server_address`: "默认服务器地址" / "Default server address"

### 测试覆盖 / Test Coverage

**Widget 测试**: 共 15 个测试，全部通过
- `test/widget/features/settings/settings_page_server_config_test.dart`: 9 个测试
- `test/widget/features/auth/login_screen_server_config_test.dart`: 6 个测试

测试覆盖了：
- 对话框显示和所有UI元素
- "恢复默认"按钮和确认对话框
- 中英文双语支持
- URL 输入字段
- 连接状态面板

### 修改的文件 / Modified Files

1. `lib/core/localization/app_localizations_en.arb` - 新增英文本地化字符串
2. `lib/core/localization/app_localizations_zh.arb` - 新增中文本地化字符串
3. `lib/shared/widgets/server_config_dialog.dart` - **新建**共享服务器配置对话框
4. `lib/features/settings/presentation/pages/settings_page.dart` - 添加服务器配置卡片，使用共享对话框
5. `lib/features/auth/view/login_screen.dart` - 添加长按触发服务器配置
6. `test/widget/features/settings/settings_page_server_config_test.dart` - **新建**Widget 测试
7. `test/widget/features/auth/login_screen_server_config_test.dart` - **新建**Widget 测试

---

## 📋 功能需求 / Functional Requirements

### FR-001: Settings Page Server Configuration Section

#### 位置 / Location
- 文件: `lib/features/settings/presentation/pages/settings_page.dart`
- 位置: 页面最上方，在所有其他设置项之前

#### UI 组件 / UI Components
```dart
// Server Configuration Section at the top of SettingsPage
Card(
  child: Column(
    children: [
      // Header
      ListTile(
        leading: Icon(Icons.dns_rounded),
        title: Text('服务器配置 / Server Configuration'),
        subtitle: Text('配置后端服务器地址 / Configure backend server address'),
      ),

      // Current connection status
      ConnectionStatusWidget(),

      // Server URL input
      TextField(
        decoration: InputDecoration(
          labelText: '服务器地址 / Server URL',
          hintText: 'http://localhost:8000',
          suffixIcon: IconButton(
            icon: Icon(Icons.paste),
            onPressed: _pasteFromClipboard,
          ),
        ),
        controller: _serverUrlController,
        keyboardType: TextInputType.url,
      ),

      // Quick action buttons
      Row(
        children: [
          // Use local address button
          ElevatedButton.icon(
            icon: Icon(Icons.computer),
            label: Text('本地 / Local'),
            onPressed: _useLocalAddress,
          ),

          // Test connection button
          ElevatedButton.icon(
            icon: Icon(Icons.wifi_find),
            label: Text('测试 / Test'),
            onPressed: _testConnection,
          ),

          // Restore defaults button
          OutlinedButton.icon(
            icon: Icon(Icons.restore),
            label: Text('恢复默认 / Restore'),
            onPressed: _restoreDefaults,
          ),
        ],
      ),

      // Save button
      FilledButton.icon(
        icon: Icon(Icons.save),
        label: Text('保存 / Save'),
        onPressed: _saveServerConfig,
      ),
    ],
  ),
)
```

#### 功能行为 / Functional Behavior
1. **加载时行为 / On Load:**
   - 从 SharedPreferences 读取已保存的服务器地址
   - 如果没有保存的地址，使用 `AppConfig.serverBaseUrl`
   - 显示当前连接状态

2. **输入验证 / Input Validation:**
   - 验证 URL 格式（scheme://host:port）
   - 支持 http 和 https 协议
   - 支持域名和 IP 地址
   - 支持 localhost 和本地网络地址

3. **连接测试 / Connection Test:**
   - 调用 `ServerHealthService.verifyConnection()`
   - 显示实时连接状态（验证中/成功/失败）
   - 显示响应时间（毫秒）
   - 显示错误信息（如果失败）

4. **保存行为 / Save Behavior:**
   - 标准化 URL（移除尾部斜杠，移除 /api/v1 后缀）
   - 保存到 SharedPreferences（key: 'server_base_url'）
   - 调用 `DioClient.updateBaseUrl()` 立即更新
   - 显示成功提示

5. **恢复默认 / Restore Defaults:**
   - 显示确认对话框
   - 重置为 `AppConfig.serverBaseUrl`
   - 自动测试新连接
   - 显示成功提示

### FR-002: Login Page Server Configuration Dialog

#### 位置 / Location
- 文件: `lib/features/auth/view/login_screen.dart`
- 位置: 登录表单右上角，齿轮图标按钮

#### UI 组件 / UI Components
```dart
// Login screen with server settings button
AppBar(
  title: Text('登录 / Login'),
  actions: [
    // Server settings button
    IconButton(
      icon: Icon(Icons.settings_ethernet),
      onPressed: _showServerConfigDialog,
      tooltip: '服务器设置 / Server Settings',
    ),
  ],
)

// Server configuration dialog
void _showServerConfigDialog() {
  showDialog(
    context: context,
    builder: (context) => ServerConfigDialog(
      currentUrl: _currentServerUrl,
      onSave: (url) => _saveServerConfig(url),
      onRestoreDefaults: () => _restoreDefaults(),
    ),
  );
}
```

#### 功能行为 / Functional Behavior
1. **对话框触发 / Dialog Trigger:**
   - 点击右上角服务器设置图标
   - 或在登录失败时提供"服务器设置"选项

2. **对话框内容 / Dialog Content:**
   - 服务器地址输入框
   - 连接状态指示器
   - "使用本地地址"快捷按钮
   - "测试连接"按钮
   - "恢复默认"按钮
   - "保存"和"取消"按钮

3. **保存后行为 / After Save:**
   - 关闭对话框
   - 刷新登录页面状态
   - 可选：自动重新测试登录状态

### FR-003: Restore Defaults Functionality

#### 默认地址逻辑 / Default Address Logic
```dart
// Get default server URL based on environment
String getDefaultServerUrl() {
  return AppConfig.serverBaseUrl;
}

// Restore defaults action
Future<void> _restoreDefaults() async {
  // Show confirmation dialog
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text('确认恢复默认 / Confirm Restore'),
      content: Text('确定要恢复为默认服务器地址吗？\n'
                    'Default: ${AppConfig.serverBaseUrl}'),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context, false),
          child: Text('取消 / Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, true),
          child: Text('确认 / Confirm'),
        ),
      ],
    ),
  );

  if (confirmed == true) {
    // Restore default
    final defaultUrl = AppConfig.serverBaseUrl;

    // Save to storage
    await LocalStorageService.saveServerBaseUrl(defaultUrl);

    // Update DioClient
    ref.read(dioClientProvider).updateBaseUrl(defaultUrl);

    // Test connection
    await _testConnection();

    // Show success message
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('已恢复默认服务器地址 / Restored default server address'),
          backgroundColor: Colors.green,
        ),
      );
    }
  }
}
```

---

## 🎨 UI/UX 设计要求 / UI/UX Design Requirements

### 设计原则 / Design Principles
1. **Material 3 Design System**: 使用 Material 3 组件和设计规范
2. **一致性**: 设置页面和登录页面的服务器设置UI保持一致
3. **可访问性**: 支持语义标签，确保屏幕阅读器可用
4. **响应式**: 支持移动端、平板和桌面布局

### 视觉规范 / Visual Specifications

#### 连接状态指示器 / Connection Status Indicator
```dart
enum ConnectionStatus {
  unverified,  // 灰色图标 / Gray icon
  verifying,   // 蓝色动画图标 / Blue animated icon
  success,     // 绿色图标 / Green icon
  failed,      // 红色图标 / Red icon
}

Widget _buildConnectionStatusIcon(ConnectionStatus status) {
  switch (status) {
    case ConnectionStatus.unverified:
      return Icon(Icons.help_outline, color: Colors.grey);
    case ConnectionStatus.verifying:
      return SizedBox(
        width: 20,
        height: 20,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    case ConnectionStatus.success:
      return Icon(Icons.check_circle, color: Colors.green);
    case ConnectionStatus.failed:
      return Icon(Icons.error, color: Colors.red);
  }
}
```

#### 颜色方案 / Color Scheme
- **Success**: `Colors.green` (连接成功)
- **Error**: `Colors.red` (连接失败)
- **Verifying**: `Theme.of(context).colorScheme.primary` (验证中)
- **Unverified**: `Colors.grey` (未验证)

#### 布局要求 / Layout Requirements
- **设置页面**: 服务器配置卡片作为第一个设置项，占据完整宽度
- **登录对话框**: 自适应大小，最大宽度 500px，移动端全屏显示
- **间距**: 使用 Material 3 标准间距（8px, 16px, 24px）

---

## 🔧 技术要求 / Technical Requirements

### TR-001: 存储服务 / Storage Service
- **现有实现**: `lib/core/storage/local_storage_service.dart`
- **方法**:
  - `saveServerBaseUrl(String url)` - 保存服务器地址
  - `getServerBaseUrl()` - 获取服务器地址
- **存储方式**: SharedPreferences
- **存储键**: `'server_base_url'`

### TR-002: 网络服务 / Network Service
- **现有实现**: `lib/core/network/dio_client.dart`
- **方法**:
  - `updateBaseUrl(String newBaseUrl)` - 动态更新 baseUrl
- **健康检查**: `lib/core/network/server_health_service.dart`
  - `verifyConnection(String baseUrl)` - 验证服务器连接

### TR-003: 状态管理 / State Management
- **Provider**: `lib/core/providers/core_providers.dart`
  - `ServerConfigNotifier` - 管理服务器配置状态
  - `ServerConfigState` - 服务器配置状态数据类

### TR-004: 默认地址配置 / Default URL Configuration
```dart
// lib/core/app/config/app_config.dart
class AppConfig {
  static String get serverBaseUrl {
    if (_serverBaseUrl.isNotEmpty) {
      return _serverBaseUrl;
    }

    switch (environment) {
      case 'production':
        return 'https://api.personalai.app';
      case 'staging':
        return 'https://api-staging.personalai.app';
      default: // development
        if (Platform.isAndroid) {
          return 'http://10.0.2.2:8000';
        }
        return 'http://localhost:8000';
    }
  }
}
```

---

## 📐 数据模型 / Data Models

### ServerConfigState
```dart
class ServerConfigState {
  final String serverUrl;
  final bool isLoading;
  final String? error;
  final bool testSuccess;
  final int? responseTimeMs;
  final ConnectionStatus connectionStatus;

  const ServerConfigState({
    required this.serverUrl,
    this.isLoading = false,
    this.error,
    this.testSuccess = false,
    this.responseTimeMs,
    this.connectionStatus = ConnectionStatus.unverified,
  });
}
```

### ConnectionStatus
```dart
enum ConnectionStatus {
  unverified,  // 未验证
  verifying,   // 验证中
  success,     // 连接成功
  failed,      // 连接失败
}
```

---

## ✅ 验收标准 / Acceptance Criteria

### AC-001: Settings Page Server Configuration
- [ ] 设置页面最上方显示服务器配置卡片
- [ ] 显示当前服务器地址和连接状态
- [ ] 输入框支持粘贴和手动输入
- [ ] "本地"按钮快速填入本地开发地址
- [ ] "测试"按钮显示实时连接状态
- [ ] "恢复默认"按钮恢复为环境默认地址
- [ ] "保存"按钮保存配置并更新网络客户端
- [ ] 显示成功/失败的提示信息
- [ ] 支持 Material 3 设计规范
- [ ] 支持中英文双语

### AC-002: Login Page Server Configuration
- [ ] 登录页面右上角显示服务器设置图标
- [ ] 点击图标弹出服务器配置对话框
- [ ] 对话框包含所有必需的设置选项
- [ ] "恢复默认"按钮功能正常
- [ ] 保存后关闭对话框并刷新登录状态
- [ ] 对话框支持移动端和桌面端布局

### AC-003: Restore Defaults Functionality
- [ ] "恢复默认"按钮显示确认对话框
- [ ] 确认后重置为 `AppConfig.serverBaseUrl`
- [ ] 重置后自动测试连接
- [ ] 显示重置成功的提示信息
- [ ] 重置后立即生效（无需重启应用）

### AC-004: Testing
- [ ] 编写 Widget 测试覆盖服务器配置 UI
- [ ] 编写单元测试覆盖恢复默认逻辑
- [ ] 手动测试各种 URL 格式
- [ ] 手动测试连接失败场景
- [ ] 测试中英文双语切换

---

## 🧪 测试计划 / Testing Plan

### WT-001: Settings Page Widget Tests
```dart
// test/widget/features/settings/settings_page_server_config_test.dart
group('SettingsPage Server Configuration', () {
  testWidgets('displays server config card at top', (tester) async {
    // Verify server config card is first item
  });

  testWidgets('shows current server URL and status', (tester) async {
    // Verify URL and status display
  });

  testWidgets('test connection button updates status', (tester) async {
    // Verify connection test behavior
  });

  testWidgets('restore defaults shows confirmation', (tester) async {
    // Verify restore defaults confirmation
  });

  testWidgets('save button persists configuration', (tester) async {
    // Verify save to storage
  });
});
```

### WT-002: Login Page Widget Tests
```dart
// test/widget/features/auth/login_screen_server_config_test.dart
group('LoginScreen Server Configuration', () {
  testWidgets('displays server settings icon in app bar', (tester) async {
    // Verify settings icon presence
  });

  testWidgets('tapping icon shows server config dialog', (tester) async {
    // Verify dialog display
  });

  testWidgets('dialog contains all required fields', (tester) async {
    // Verify dialog content
  });

  testWidgets('restore defaults button works in dialog', (tester) async {
    // Verify restore defaults in dialog
  });
});
```

### UT-001: Unit Tests
```dart
// test/unit/features/settings/server_config_notifier_test.dart
group('ServerConfigNotifier', () {
  test('restoreDefaults resets to AppConfig URL', () {
    // Verify restore defaults logic
  });

  test('updateServerUrl saves to storage', () {
    // Verify save behavior
  });

  test('testConnection updates connection status', () {
    // Verify test connection behavior
  });
});
```

---

## 📝 API 依赖 / API Dependencies

### 现有 API
- **GET /health** - 服务器健康检查
  - 响应: `{"status": "healthy", "timestamp": "..."}`

### 新增 API
无新增 API，使用现有健康检查接口。

---

## 🚀 实现计划 / Implementation Plan

### Phase 1: Settings Page Enhancement (Priority: High)
**负责人**: Frontend Developer 🖥️
**预计时间**: 2-3 小时

1. 移除隐藏的服务器配置功能（版本号5次点击）
2. 在设置页面最上方添加服务器配置卡片
3. 实现连接状态显示
4. 实现恢复默认按钮

### Phase 2: Login Page Enhancement (Priority: High)
**负责人**: Frontend Developer 🖥️
**预计时间**: 2-3 小时

1. 在登录页面添加服务器设置图标
2. 创建服务器配置对话框组件
3. 实现对话框与设置页面的功能一致性
4. 实现保存后刷新登录状态

### Phase 3: Testing (Priority: High)
**负责人**: Test Engineer 🧪
**预计时间**: 2 小时

1. 编写 Widget 测试
2. 编写单元测试
3. 手动测试各种场景
4. 中英文双语验证

### Phase 4: Documentation (Priority: Medium)
**负责人**: Product Manager 📋
**预计时间**: 1 小时

1. 更新用户文档
2. 更新开发者文档
3. 创建功能演示

---

## 📚 参考文档 / References

1. **Material 3 Design Guidelines**: https://m3.material.io/
2. **Flutter SharedPreferences**: https://pub.dev/packages/shared_preferences
3. **Dio HTTP Client**: https://pub.dev/packages/dio
4. **现有服务器配置实现**: `lib/features/settings/presentation/pages/settings_page.dart:966-1284`
5. **网络客户端实现**: `lib/core/network/dio_client.dart`
6. **健康检查服务**: `lib/core/network/server_health_service.dart`

---

## 🔄 变更历史 / Change History

| 日期 / Date | 版本 / Version | 变更内容 / Changes | 作者 / Author |
|-------------|----------------|-------------------|---------------|
| 2025-12-30 | 1.0 | 初始需求创建 / Initial requirements | Product Manager 📋 |

---

## 📎 附录 / Appendix

### A. 当前服务器配置隐藏功能截图位置
当前隐藏功能位于设置页面版本号5次点击触发，需要将此功能改为可见的设置项。

### B. 默认服务器地址环境配置
- **Production**: `https://api.personalai.app`
- **Staging**: `https://api-staging.personalai.app`
- **Development**:
  - Android Emulator: `http://10.0.2.2:8000`
  - 其他平台: `http://localhost:8000`

### C. URL 标准化规则
- 移除尾部斜杠: `http://localhost:8000/` → `http://localhost:8000`
- 移除 /api/v1 后缀: `http://localhost:8000/api/v1` → `http://localhost:8000`
- 保留协议和端口: `https://api.example.com:8080` → 保持不变

---

**状态 / Status**: 📋 Active / 进行中
**下一步 / Next Step**: 分配给 Frontend Developer 开始实现 / Assign to Frontend Developer for implementation
