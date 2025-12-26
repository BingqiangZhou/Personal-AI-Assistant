#!/bin/bash
# Personal AI Assistant - 创建发布 Tag / Create Release Tag
#
# 使用方法 / Usage:
#   ./scripts/create-release.sh [version] [pre-release-type]
#
# 示例 / Examples:
#   ./scripts/create-release.sh 1.0.0          # 正式版本
#   ./scripts/create-release.sh 1.1.0 alpha    # Alpha 预发布版本
#   ./scripts/create-release.sh 1.2.0 beta     # Beta 预发布版本
#   ./scripts/create-release.sh 2.0.0 rc       # Release Candidate

set -e

VERSION=$1
PRE_TYPE=$2

if [ -z "$VERSION" ]; then
  echo "❌ 错误 / Error: 请提供版本号 / Please provide version number"
  echo "使用方法 / Usage: $0 [version] [pre-release-type]"
  echo "示例 / Example: $0 1.0.0"
  exit 1
fi

# 验证版本号格式 / Validate version format
if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "❌ 错误 / Error: 版本号格式无效 / Invalid version format"
  echo "预期格式 / Expected format: X.Y.Z (如/eg 1.0.0)"
  exit 1
fi

# 构建 tag 名称 / Build tag name
if [ -n "$PRE_TYPE" ]; then
  case $PRE_TYPE in
    alpha|beta|rc|preview)
      TAG_NAME="v${VERSION}-${PRE_TYPE}"
      ;;
    *)
      echo "❌ 错误 / Error: 无效的预发布类型 / Invalid pre-release type"
      echo "支持类型 / Supported types: alpha, beta, rc, preview"
      exit 1
      ;;
  esac
else
  TAG_NAME="v${VERSION}"
fi

# 检查 tag 是否已存在 / Check if tag already exists
if git rev-parse "$TAG_NAME" >/dev/null 2>&1; then
  echo "❌ 错误 / Error: Tag $TAG_NAME 已存在 / already exists"
  echo "请使用不同的版本号 / Please use a different version number"
  exit 1
fi

# 显示发布信息 / Display release info
echo ""
echo "=================================="
echo "📦 准备创建发布 / Preparing Release"
echo "=================================="
echo "版本 / Version: $VERSION"
echo "Tag / Tag: $TAG_NAME"
if [ -n "$PRE_TYPE" ]; then
  echo "类型 / Type: Pre-release ($PRE_TYPE)"
else
  echo "类型 / Type: Official Release"
fi
echo "=================================="
echo ""

# 确认 / Confirm
read -p "确认创建此发布？/ Confirm to create this release? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "❌ 已取消 / Cancelled"
  exit 1
fi

# 更新版本号（可选） / Update version number (optional)
echo ""
echo "📝 更新 pubspec.yaml 版本号 / Updating pubspec.yaml version number"

# 更新 frontend/pubspec.yaml
if [ -f "frontend/pubspec.yaml" ]; then
  sed -i "s/^version: .*/version: ${VERSION}+1/" frontend/pubspec.yaml
  echo "✅ frontend/pubspec.yaml 已更新 / updated"
fi

# 更新 frontend/desktop/pubspec.yaml
if [ -f "frontend/desktop/pubspec.yaml" ]; then
  sed -i "s/^version: .*/version: ${VERSION}+1/" frontend/desktop/pubspec.yaml
  echo "✅ frontend/desktop/pubspec.yaml 已更新 / updated"
fi

# 提交版本号更改 / Commit version changes
echo ""
echo "💾 提交版本号更改 / Committing version changes"
git add frontend/pubspec.yaml frontend/desktop/pubspec.yaml
git commit -m "chore: bump version to $VERSION" || echo "ℹ️  没有版本号更改需要提交 / No version changes to commit"

# 创建并推送 tag / Create and push tag
echo ""
echo "🏷️  创建 tag / Creating tag: $TAG_NAME"
git tag -a "$TAG_NAME" -m "Release $TAG_NAME"

echo ""
echo "📤 推送 tag 到远程仓库 / Pushing tag to remote repository"
git push origin "$TAG_NAME"

echo ""
echo "✅ 成功！/ Success!"
echo ""
echo "🚀 GitHub Actions 将开始构建 / GitHub Actions will now start building:"
echo "   - Android APK & AAB"
echo "   - Windows 可执行文件 / executable"
echo "   - Linux 二进制文件 / binary"
echo "   - macOS 应用 / application"
echo ""
echo "📊 查看构建进度 / View build progress:"
echo "   https://github.com/${GITHUB_REPOSITORY:-your-username/your-repo}/actions"
echo ""
