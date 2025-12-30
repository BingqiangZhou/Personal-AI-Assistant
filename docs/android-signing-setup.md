# Android Signing Configuration Setup
# Android 签名配置设置指南

## 问题说明 / Problem Description

**错误信息 / Error Message:**
```
App not installed as package conflicts with an existing package
```

**根本原因 / Root Cause:**
1. 每次构建时签名不同 (Different signature each build)
2. versionCode 没有递增 (versionCode not incrementing)

---

## 解决方案 / Solution Overview

本配置提供了两种签名方式：
This configuration provides two signing methods:

1. **开发模式 / Development Mode**: 使用 debug 签名 (Use debug signing)
2. **生产模式 / Production Mode**: 使用自定义 keystore 签名 (Use custom keystore signing)

---

## 方案一：开发模式（推荐用于本地开发）
## Option 1: Development Mode (Recommended for Local Development)

### 无需任何配置 / No Configuration Required

默认情况下，应用会使用 debug 签名配置。
By default, the app uses debug signing configuration.

### 构建命令 / Build Commands

```bash
# 确保每次构建使用递增的版本号
# Make sure to use an incremented version number for each build

cd frontend

# 方式1: 直接指定版本号和构建号
# Method 1: Specify version and build number directly
flutter build apk --release --build-name=1.0.0 --build-number=1

# 方式2: 使用 pubspec.yaml 中的版本
# Method 2: Use version from pubspec.yaml
flutter build apk --release

# 更新 pubspec.yaml 中的版本号
# Update version in pubspec.yaml
# version: 1.0.0+2
```

### ⚠️ 重要提示 / Important Note

**Debug 签名在不同机器上不同，因此：**
**Debug signatures vary across machines, therefore:**

- ✅ 同一台机器构建的 APK 可以互相覆盖安装
  ✅ APKs built on the same machine can overwrite each other

- ❌ 不同机器构建的 APK 无法覆盖安装
  ❌ APKs from different machines cannot overwrite each other

---

## 方案二：生产模式（推荐用于发布）
## Option 2: Production Mode (Recommended for Release)

### Step 1: 生成 Keystore / Generate Keystore

```bash
cd frontend/android/app

# 生成 release keystore
# Generate release keystore
keytool -genkey -v -keystore release.keystore -alias release \
  -keyalg RSA -keysize 2048 -validity 10000

# 输入信息示例 / Example input:
# Keystore password: [设置一个强密码 / Set a strong password]
# Key alias: release (已设置 / Already set)
# Key password: [设置一个强密码 / Set a strong password]
# CN: Your Name or Team Name
# OU: Development
# O: Your Organization
# L: Your City
# ST: Your State/Province
# C: Country Code (e.g., CN, US)
```

### Step 2: 创建 key.properties 文件 / Create key.properties File

```bash
cd frontend/android/app

# 复制示例文件
# Copy example file
cp key.properties.example key.properties

# 编辑文件，填入你的 keystore 信息
# Edit file and fill in your keystore information
```

**key.properties 内容 / key.properties contents:**

```properties
storeFile=release.keystore
storePassword=your_keystore_password
keyAlias=release
keyPassword=your_key_password
```

### Step 3: 验证配置 / Verify Configuration

```bash
cd frontend

# 构建测试
# Build for testing
flutter build apk --release --build-name=1.0.0 --build-number=1
```

构建日志应该显示：
Build log should show:
```
📱 Using keystore signing configuration from key.properties
```

---

## GitHub Actions 配置 / GitHub Actions Configuration

### 添加 Secrets / Add Secrets

在 GitHub 仓库设置中添加以下 Secrets：
Add the following Secrets in GitHub repository settings:

1. **ANDROID_KEYSTORE_BASE64**: Keystore 文件的 base64 编码
   Base64 encoded keystore file

   ```bash
   # Windows PowerShell
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("frontend\android\app\release.keystore"))

   # macOS/Linux
   base64 -i frontend/android/app/release.keystore | pbcopy  # macOS
   base64 -w 0 frontend/android/app/release.keystore        # Linux
   ```

2. **ANDROID_KEYSTORE_PASSWORD**: Keystore 密码
   Keystore password

3. **ANDROID_KEY_ALIAS**: 密钥别名 (默认: `release`)
   Key alias (default: `release`)

4. **ANDROID_KEY_PASSWORD**: 密钥密码
   Key password

### 发布流程 / Release Process

```bash
# 创建并推送版本标签
# Create and push version tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions 将自动构建并发布
# GitHub Actions will build and publish automatically
```

---

## 版本管理 / Version Management

### 版本号格式 / Version Format

```
version: 1.0.0+2
          ↑    ↑
          |    |
       build-name  build-number
       (版本名)   (构建号)
```

### 发布版本 / Release Versions

```bash
# 稳定版本 / Stable version
v1.0.0

# 预发布版本 / Pre-release version
v1.0.0-beta.1
v1.0.0-rc.1
v1.0.0-alpha.1
```

---

## 故障排查 / Troubleshooting

### 问题 1: 签名冲突 / Issue 1: Signature Conflict

**错误 / Error:**
```
App not installed as package conflicts with an existing package
```

**解决方案 / Solution:**

1. 卸载旧版本 / Uninstall old version
2. 使用固定的 keystore 签名 / Use fixed keystore signing
3. 确保 versionCode 递增 / Ensure versionCode increments

### 问题 2: 构建失败 / Issue 2: Build Fails

**检查项 / Checklist:**

```bash
# 检查 Gradle 版本 / Check Gradle version
cd frontend/android
./gradlew --version

# 清理构建缓存 / Clean build cache
cd frontend
flutter clean
cd android
./gradlew clean

# 重新构建 / Rebuild
cd ..
flutter build apk --release
```

### 问题 3: key.properties 不生效 / Issue 3: key.properties Not Working

**检查 / Check:**

```bash
# 确认文件存在 / Confirm file exists
ls -la frontend/android/app/key.properties

# 检查构建日志 / Check build log
flutter build apk --release --verbose
```

应该看到：
Should see:
```
📱 Using keystore signing configuration from key.properties
```

如果看到：
If you see:
```
🔧 Using debug signing configuration (for development)
```

说明 key.properties 文件不存在或格式错误。
It means key.properties doesn't exist or has incorrect format.

---

## 最佳实践 / Best Practices

1. **版本管理 / Version Management**
   - 每次发布都递增 build-number
     Increment build-number for each release
   - 使用语义化版本号 (Semantic Versioning)
     Use semantic versioning (MAJOR.MINOR.PATCH)

2. **签名管理 / Signing Management**
   - 妥善保管 keystore 文件和密码
     Keep keystore file and passwords secure
   - 定期备份 keystore 文件
     Backup keystore file regularly
   - 不要将 keystore 提交到版本控制
     Never commit keystore to version control

3. **CI/CD / Continuous Integration**
   - 在 GitHub Actions 中使用正式签名
     Use official signing in GitHub Actions
   - 本地开发使用 debug 签名
     Use debug signing for local development
