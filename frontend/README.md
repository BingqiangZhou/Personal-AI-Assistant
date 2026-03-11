# Personal AI Assistant - Flutter 前端

跨平台移动应用，提供播客订阅管理、音频播放、AI 对话等功能。

## 技术栈

| 技术 | 说明 |
|------|------|
| Flutter 3.x | 跨平台 UI 框架 |
| Material 3 | UI 设计系统 |
| Riverpod 2.x | 状态管理 |
| GoRouter | 路由管理 |
| Dio | HTTP 客户端 |
| Hive | 本地存储 |
| audioplayers | 音频播放 |

## 项目结构

```
frontend/lib/
├── core/                   # 核心层
│   ├── constants/         # 常量定义
│   ├── error/             # 错误处理
│   ├── network/           # 网络客户端
│   ├── storage/           # 本地存储
│   └── utils/             # 工具函数
│
├── shared/                 # 共享层
│   ├── widgets/           # 可复用组件
│   ├── theme/             # Material 3 主题
│   └── extensions/        # 扩展方法
│
└── features/               # 功能模块
    ├── auth/              # 登录、注册、密码重置
    ├── home/              # 首页
    ├── podcast/           # 播客订阅、单集、播放器
    ├── ai/                # AI 模型配置
    ├── profile/           # 用户资料
    └── admin/             # 管理面板
```

## 快速开始

### 1. 安装依赖

```bash
cd frontend
flutter pub get
```

### 2. 运行应用

```bash
flutter run

# 指定设备
flutter run -d chrome          # Web
flutter run -d windows         # Windows
flutter run -d macos           # macOS
flutter run -d <设备ID>         # 移动设备
```

### 3. 构建发布

```bash
# Android
flutter build apk --release

# iOS
flutter build ios --release

# Web
flutter build web
```

## 测试要求

### Widget 测试

**必须为每个页面编写 Widget 测试**，测试文件放在 `test/widget/` 目录。

```bash
# 运行 Widget 测试
flutter test test/widget/

# 运行所有测试
flutter test

# 运行特定文件
flutter test test/widget/auth_test.dart
```

### 测试标准

- 页面渲染测试
- 用户交互测试
- 状态变化测试

### 多屏幕测试

必须在以下屏幕尺寸下测试：
- 移动端 (<600dp)
- 平板 (600dp-840dp)
- 桌面 (>840dp)

## 开发规范

### 代码规范

- 使用 Material 3 组件
- 使用 Riverpod 进行状态管理
- 遵循 Flutter 官方代码风格

### 响应式设计

使用 `AdaptiveScaffoldWrapper` 实现自适应布局：

```dart
AdaptiveScaffoldWrapper(
  mobileLayout: MobileLayout(),
  desktopLayout: DesktopLayout(),
)
```

### 国际化

项目支持中英文双语，字符串资源在 `lib/l10n/` 目录。

## 常用命令

```bash
# 代码分析
flutter analyze

# 格式化代码
flutter format .

# 运行测试
flutter test

# 构建 APK
flutter build apk --release

# 清理缓存
flutter clean
```

## 相关文档

- [测试架构指南](docs/test_architecture_guide.md)
- [部署指南](../docs/DEPLOYMENT.md)
- [Android 签名配置](../docs/ANDROID_SIGNING.md)
