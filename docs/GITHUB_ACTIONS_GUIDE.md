# GitHub Actions CI/CD 使用指南 / GitHub Actions CI/CD Guide

## 概述 / Overview

本项目使用 GitHub Actions 实现自动化 CI/CD 流程，包括：
- **持续集成 (CI)**: 每次推送或 PR 时自动运行测试和代码检查
- **持续发布 (CD)**: 推送版本 tag 时自动构建多平台应用并发布到 GitHub Release

This project uses GitHub Actions for automated CI/CD pipeline, including:
- **Continuous Integration**: Automated testing and code checks on every push or PR
- **Continuous Deployment**: Multi-platform builds and GitHub Release publishing on version tags

---

## 工作流说明 / Workflows Overview

### 1. CI Workflow (`.github/workflows/ci.yml`)

**触发条件 / Triggers:**
- 推送到 `main` 或 `develop` 分支
- 针对 `main` 或 `develop` 的 Pull Request

**执行任务 / Tasks:**

| 平台 / Platform | 检查项 / Checks |
|-----------------|-----------------|
| Backend (Python/FastAPI) | mypy, black, isort, flake8, pytest |
| Frontend (Flutter Mobile) | analyze, format, test (sharded), build web |
| Desktop (Flutter Desktop) | analyze, test on Linux/Windows/macOS |

### 2. Release Workflow (`.github/workflows/release.yml`)

**触发条件 / Triggers:**
- 推送匹配 `v*.*.*` 格式的 tag (如 `v1.0.0`, `v2.1.3-beta`)

**构建平台 / Build Platforms:**

| 平台 / Platform | 输出 / Output |
|-----------------|---------------|
| Android | APK (arm64, arm), AAB (Play Store) |
| Windows | ZIP 包含可执行文件 |
| Linux | TAR.GZ 压缩包 |
| macOS | ZIP 包含 .app 应用 |

---

## 快速开始 / Quick Start

### 创建一个新版本 / Create a New Release

#### 方式一：使用发布脚本（推荐）/ Method 1: Using Release Script (Recommended)

**Linux/macOS:**
```bash
# 正式版本 / Official release
./scripts/create-release.sh 1.0.0

# 预发布版本 / Pre-release
./scripts/create-release.sh 1.1.0 alpha
./scripts/create-release.sh 1.2.0 beta
./scripts/create-release.sh 2.0.0 rc
```

**Windows (PowerShell):**
```powershell
# 正式版本 / Official release
.\scripts\create-release.ps1 -Version 1.0.0

# 预发布版本 / Pre-release
.\scripts\create-release.ps1 -Version 1.1.0 -PreReleaseType alpha
```

#### 方式二：手动创建 Tag / Method 2: Manual Tag Creation

```bash
# 1. 更新版本号（可选）
# Update version number in pubspec.yaml (optional)
vim frontend/pubspec.yaml
vim frontend/desktop/pubspec.yaml

# 2. 提交更改
git add frontend/pubspec.yaml frontend/desktop/pubspec.yaml
git commit -m "chore: bump version to 1.0.0"

# 3. 创建并推送 tag
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0
```

### 查看构建状态 / View Build Status

访问 GitHub Actions 页面：
```
https://github.com/YOUR_USERNAME/YOUR_REPO/actions
```

---

## 语义化版本号 / Semantic Versioning

遵循 [SemVer 2.0.0](https://semver.org/) 规范：

| 版本号 / Version | 类型 / Type | 说明 / Description |
|------------------|-------------|-------------------|
| `1.0.0` | 正式版本 / Official | 稳定的发布版本 |
| `1.0.0-alpha` | Alpha | 内部测试版本 |
| `1.0.0-beta` | Beta | 公开测试版本 |
| `1.0.0-rc` | Release Candidate | 候选发布版本 |

**版本号格式 / Version Format:**
```
MAJOR.MINOR.PATCH[-PRERELEASE]
```

- **MAJOR**: 不兼容的 API 变更
- **MINOR**: 向后兼容的功能新增
- **PATCH**: 向后兼容的问题修复

---

## 配置说明 / Configuration

### 环境变量 / Environment Variables

在 `.github/workflows/*.yml` 中配置：

```yaml
env:
  FLUTTER_VERSION: '3.24.0'  # Flutter 版本
  JAVA_VERSION: '17'          # Java 版本
  JAVA_DISTRIBUTION: 'temurin' # Java 发行版
```

### Secrets 配置（可选） / Secrets Configuration (Optional)

用于 Android 应用签名：

1. 进入仓库设置 / Go to repository settings
   `Settings` → `Secrets and variables` → `Actions`

2. 添加以下 Secrets / Add the following secrets:

| Secret 名称 / Name | 描述 / Description |
|-------------------|-------------------|
| `KEYSTORE_BASE64` | Base64 编码的 Android keystore |
| `KEYSTORE_PASSWORD` | Keystore 密码 |
| `KEY_PASSWORD` | 密钥密码 |
| `KEY_ALIAS` | 密钥别名 |

详细配置请参考：[Android 签名配置指南](./ANDROID_SIGNING.md)

---

## 更新日志 / Changelog

更新日志自动从 Git 提交记录生成：

```
### 📝 更新日志 / Changelog

**Changes since v0.9.0:**

- feat: add new podcast player feature (abc123)
- fix: resolve login issue (def456)
- docs: update README (ghi789)

**Full Version:** 1.0.0
**Release Date:** 2025-01-15 10:30:00 UTC
```

### 自定义更新日志 / Custom Changelog

如果你想在发布前编辑更新日志：

1. 等待 CI 检查通过
2. 创建 tag 但不要立即推送
3. 创建 `CHANGELOG.md` 文件并写入自定义内容
4. 提交 `CHANGELOG.md`
5. 推送 tag

---

## 故障排查 / Troubleshooting

### 构建失败 / Build Failed

**检查清单 / Checklist:**

1. **CI 失败 / CI Failed**
   - 检查代码是否通过所有测试 / Check if all tests pass
   - 运行 `flutter analyze` 检查代码问题 / Run `flutter analyze` for code issues
   - 确保 `black`, `isort`, `flake8` 检查通过 / Ensure linter checks pass

2. **构建超时 / Build Timeout**
   - GitHub Actions 有时间限制（6 小时）
   - 如果构建时间过长，考虑优化构建步骤

3. **Flutter 依赖问题 / Flutter Dependency Issues**
   - 清理缓存：`flutter clean`
   - 重新获取依赖：`flutter pub get`
   - 检查 `pubspec.yaml` 和 `pubspec.lock`

### Release 发布失败 / Release Publishing Failed

1. **Tag 已存在 / Tag Already Exists**
   ```bash
   # 查看已存在的 tag
   git tag -l

   # 删除本地和远程 tag（如果需要）
   git tag -d v1.0.0
   git push origin :refs/tags/v1.0.0
   ```

2. **权限不足 / Insufficient Permissions**
   - 确保 GitHub Token 有写入权限
   - 检查 `Settings` → `Actions` → `General` → `Workflow permissions`

3. **Artifact 缺失 / Missing Artifacts**
   - 检查构建日志确认构建步骤是否成功
   - 验证 artifact 上传步骤是否正确

---

## 本地测试 / Local Testing

在推送 tag 之前，建议本地测试构建：

### 测试 Android 构建
```bash
cd frontend
flutter build apk --release
flutter build appbundle --release
```

### 测试 Windows 构建
```bash
cd frontend/desktop
flutter config --enable-windows-desktop
flutter build windows --release
```

### 测试 Linux 构建
```bash
cd frontend/desktop
flutter config --enable-linux-desktop
flutter build linux --release
```

### 测试 macOS 构建
```bash
cd frontend/desktop
flutter config --enable-macos-desktop
flutter build macos --release
```

---

## 常见问题 / FAQ

### Q: 如何取消正在运行的构建？

**A:** 进入 GitHub Actions 页面，点击右上角的 `Cancel run` 按钮。

### Q: 如何重新运行失败的构建？

**A:** 在 Actions 页面找到失败的工作流，点击 `Re-run all jobs`。

### Q: 构建时间太长怎么办？

**A:**
1. 使用缓存（已配置）
2. 减少测试数量或使用并行测试
3. 考虑只构建必要的平台

### Q: 如何下载构建产物？

**A:**
1. 在 GitHub Release 页面下载
2. 或者在 Actions 页面的 Artifacts 区域下载（保留 90 天）

### Q: 支持 iOS 构建吗？

**A:** iOS 构建需要 macOS 环境和 Apple 开发者账号。如需添加，请配置 macOS runner 和相关证书。

---

## 参考资料 / References

- [GitHub Actions 文档](https://docs.github.com/en/actions)
- [Flutter 构建和发布](https://docs.flutter.dev/deployment)
- [语义化版本](https://semver.org/lang/zh-CN/)
- [Android 应用签名](./ANDROID_SIGNING.md)

---

## 更新日志 / Changelog

| 日期 / Date | 版本 / Version | 更新 / Update |
|-------------|----------------|---------------|
| 2025-01-XX | 1.0.0 | 初始版本 / Initial version |
