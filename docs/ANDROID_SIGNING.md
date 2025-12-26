# Android 应用签名配置指南 / Android App Signing Configuration Guide

## 概述 / Overview

要发布正式的 Android 应用到 Google Play Store，需要对 APK/AAB 进行签名。本指南介绍如何配置 Android 应用签名。

To publish official Android apps to Google Play Store, you need to sign the APK/AAB. This guide explains how to configure Android app signing.

---

## 方式一：GitHub Actions 自动签名（推荐） / Method 1: GitHub Actions Auto Signing (Recommended)

### 步骤 1: 生成签名密钥 / Step 1: Generate Signing Keystore

在本地运行以下命令生成签名密钥：

```bash
keytool -genkey -v -keystore release-keystore.jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias release \
  -dname "CN=Your Name, OU=Development, O=Your Organization, L=City, ST=State, C=US"
```

### 步骤 2: 将 keystore 转换为 Base64 / Step 2: Convert Keystore to Base64

```bash
# Linux/macOS
base64 -i release-keystore.jks | pbcopy

# Windows (PowerShell)
[Convert]::ToBase64String([IO.File]::ReadAllBytes("release-keystore.jks")) | Set-Clipboard
```

### 步骤 3: 配置 GitHub Secrets / Step 3: Configure GitHub Secrets

在 GitHub 仓库设置中添加以下 Secrets：

Navigate to: `Settings` → `Secrets and variables` → `Actions` → `New repository secret`

| Secret 名称 / Name | 描述 / Description | 示例 / Example |
|-------------------|-------------------|----------------|
| `KEYSTORE_BASE64` | Base64 编码的 keystore 文件 | `(粘贴 Base64 内容)` |
| `KEYSTORE_PASSWORD` | Keystore 密码 | `your-keystore-password` |
| `KEY_PASSWORD` | 密钥密码 | `your-key-password` |
| `KEY_ALIAS` | 密钥别名 | `release` |

### 步骤 4: 更新 Release Workflow / Step 4: Update Release Workflow

在 `.github/workflows/release.yml` 的 Android 构建步骤中添加签名步骤：

```yaml
- name: Decode keystore
  run: |
    echo "${{ secrets.KEYSTORE_BASE64 }}" | base64 --decode > release-keystore.jks

- name: Sign APK
  working-directory: frontend
  run: |
    # 找到生成的 APK
    APK_PATH=$(find build/app/outputs/flutter-apk -name "*.apk" | head -n1)
    # 使用 jarsigner 签名
    jarsigner -verbose -sigalg SHA256withRSA \
      -digestalg SHA256 \
      -keystore ../release-keystore.jks \
      -storepass "${{ secrets.KEYSTORE_PASSWORD }}" \
      -keypass "${{ secrets.KEY_PASSWORD }}" \
      "$APK_PATH" \
      "${{ secrets.KEY_ALIAS }}"

- name: Verify APK signature
  working-directory: frontend
  run: |
    APK_PATH=$(find build/app/outputs/flutter-apk -name "*.apk" | head -n1)
    jarsigner -verify -verbose -certs "$APK_PATH"
```

---

## 方式二：本地签名后上传 / Method 2: Sign Locally Then Upload

### 步骤 1: 构建未签名的 APK / Step 1: Build Unsigned APK

```bash
cd frontend
flutter build apk --release
```

### 步骤 2: 签名 APK / Step 2: Sign APK

```bash
jarsigner -verbose -sigalg SHA256withRSA \
  -digestalg SHA256 \
  -keystore release-keystore.jks \
  -storepass your-keystore-password \
  -keypass your-key-password \
  build/app/outputs/flutter-apk/app-release.apk \
  release
```

### 步骤 3: 验证签名 / Step 3: Verify Signature

```bash
jarsigner -verify -verbose -certs build/app/outputs/flutter-apk/app-release.apk
```

### 步骤 4: 对齐 APK（优化） / Step 4: Zipalign APK (Optimize)

```bash
zipalign -v -p 4 build/app/outputs/flutter-apk/app-release.apk app-release-aligned.apk
```

---

## 安全注意事项 / Security Notes

### ⚠️ 重要 / IMPORTANT

1. **不要将 keystore 文件提交到 Git 仓库**
   **Never commit keystore files to Git repository**

2. **确保 keystore 密码强度足够**
   **Ensure keystore password is strong enough**

3. **妥善备份 keystore 文件**
   **Keep a secure backup of your keystore file**

   > 一旦丢失 keystore，你将无法更新应用！
   > Once you lose the keystore, you cannot update your app!

4. **使用 .gitignore 排除敏感文件**
   **Use .gitignore to exclude sensitive files**

   添加到 `.gitignore`:
   ```
   *.jks
   *.keystore
   release-key.properties
   ```

---

## Android Keytool 命令参考 / Keytool Command Reference

### 生成新密钥 / Generate New Key
```bash
keytool -genkey -v -keystore [filename].jks \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -alias [alias]
```

### 查看密钥信息 / View Key Information
```bash
keytool -list -v -keystore [filename].jks -alias [alias]
```

### 更改密钥密码 / Change Key Password
```bash
keytool -keypasswd -alias [alias] -keystore [filename].jks
```

### 导出证书 / Export Certificate
```bash
keytool -export -alias [alias] -keystore [filename].jks -file certificate.cer
```

---

## Google Play App Signing

发布到 Google Play 时，你可以选择：

1. **自己管理密钥** - 你保留密钥并上传签名的 AAB
2. **让 Google 管理密钥** - Google 为你生成并管理密钥

推荐使用 **Google Play App Signing**，因为它：
- 提供更安全的密钥管理
- 即使丢失密钥也能更新应用
- 自动处理密钥轮换

参考：https://support.google.com/googleplay/android-developer/answer/7384423
