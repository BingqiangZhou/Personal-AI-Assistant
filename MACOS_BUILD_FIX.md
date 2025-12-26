# macOS 构建错误修复说明

## 问题描述

GitHub Action 在执行 macOS 构建时出现错误，主要原因是 **工作目录配置错误**。

## 根本原因分析

### 项目结构分析
```
frontend/
├── lib/main.dart                    # 主应用入口
├── pubspec.yaml                    # 主项目配置
├── android/                        # Android 配置
├── ios/                            # iOS 配置
├── macos/                          # macOS 原生配置
├── windows/                        # Windows 原生配置
├── linux/                          # Linux 原生配置
├── desktop/                        # 桌面专用代码
│   ├── lib/                        # 桌面 UI 组件
│   ├── pubspec.yaml               # 桌面依赖
│   └── test/                       # 桌面测试
└── build/                          # 构建输出目录
```

### 原始错误配置
```yaml
# ❌ 错误的配置
- name: Build macOS
  working-directory: frontend/desktop    # ← 错误！
  run: flutter build macos
```

**问题：**
1. `frontend/desktop` 目录下没有 `macos/` 子目录
2. `frontend/desktop` 目录下没有 `main.dart`
3. Flutter 构建需要在包含 `main.dart` 和 `macos/` 配置的目录执行

## 修复方案

### 1. macOS 构建修复
```yaml
# ✅ 正确的配置
- name: Build macOS
  working-directory: frontend    # ← 修正为 frontend
  run: flutter build macos \
    --release \
    --build-number=${{ needs.prepare-release.outputs.version_no_v }}
```

### 2. Windows 构建修复
```yaml
# ✅ 正确的配置
- name: Build Windows
  working-directory: frontend    # ← 修正为 frontend
  run: flutter build windows \
    --release \
    --build-number=${{ needs.prepare-release.outputs.version_no_v }}
```

### 3. Linux 构建修复
```yaml
# ✅ 正确的配置
- name: Build Linux
  working-directory: frontend    # ← 修正为 frontend
  run: flutter build linux \
    --release \
    --build-number=${{ needs.prepare-release.outputs.version_no_v }}
```

### 4. 路径更新
所有相关的路径也需要相应更新：

**macOS:**
- 构建目录: `frontend/build/macos/Build/Products/Release`
- 压缩目录: `frontend/build/macos/Build/Products/Release`

**Windows:**
- 构建目录: `frontend/build/windows/runner/Release`
- 压缩目录: `frontend/build/windows/runner/Release`

**Linux:**
- 构建目录: `frontend/build/linux/x64/release/bundle`
- 压缩目录: `frontend/build/linux/x64/release/bundle`

## 为什么 Android 构建没有问题？

Android 构建配置：
```yaml
- name: Build APK
  working-directory: frontend    # ✅ 正确
  run: flutter build apk
```

Android 构建本来就在 `frontend/` 目录，所以没有问题。

## 项目结构说明

### 桌面开发模式
在开发时，可以使用：
```bash
cd frontend/desktop
flutter run -d macos      # 这样可以工作，因为会自动找到父项目的配置
```

### 构建模式
在 CI/CD 构建时，必须在主项目目录：
```bash
cd frontend
flutter build macos       # 正确的构建方式
flutter build windows
flutter build linux
```

## 验证修复

修复后的 workflow 将：
1. ✅ 在正确的目录执行构建命令
2. ✅ 找到 `main.dart` 入口文件
3. ✅ 找到平台特定的配置文件（macos/, windows/, linux/）
4. ✅ 生成正确的构建输出
5. ✅ 正确打包和上传 artifact

## 相关文件

- `.github/workflows/release.yml` - 已修复的 Release workflow
- `frontend/pubspec.yaml` - 主项目配置
- `frontend/desktop/pubspec.yaml` - 桌面专用依赖
- `frontend/macos/` - macOS 原生配置
- `frontend/windows/` - Windows 原生配置
- `frontend/linux/` - Linux 原生配置

## 总结

**核心问题：** `working-directory` 配置错误
**解决方案：** 所有桌面构建都应在 `frontend/` 目录执行
**影响范围：** macOS、Windows、Linux 构建

修复后，GitHub Action 将能正确构建所有桌面平台的应用。