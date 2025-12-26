# Personal AI Assistant - 创建发布 Tag (PowerShell 版本)
# Create Release Tag Script for Windows

param(
  [Parameter(Mandatory=$true, HelpMessage="版本号，例如: 1.0.0")]
  [string]$Version,

  [Parameter(Mandatory=$false)]
  [ValidateSet("alpha", "beta", "rc", "preview")]
  [string]$PreReleaseType
)

$ErrorActionPreference = "Stop"

# 验证版本号格式
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
  Write-Host "❌ 错误 / Error: 版本号格式无效 / Invalid version format" -ForegroundColor Red
  Write-Host "预期格式 / Expected format: X.Y.Z (如/eg 1.0.0)" -ForegroundColor Yellow
  exit 1
}

# 构建 tag 名称
if ($PreReleaseType) {
  $tagName = "v${Version}-${PreReleaseType}"
  $releaseType = "Pre-release ($PreReleaseType)"
} else {
  $tagName = "v${Version}"
  $releaseType = "Official Release"
}

# 检查 tag 是否已存在
$tagExists = git tag -l "$tagName"
if ($tagExists) {
  Write-Host "❌ 错误 / Error: Tag $tagName 已存在 / already exists" -ForegroundColor Red
  Write-Host "请使用不同的版本号 / Please use a different version number" -ForegroundColor Yellow
  exit 1
}

# 显示发布信息
Write-Host ""
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "📦 准备创建发布 / Preparing Release" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "版本 / Version: $Version" -ForegroundColor White
Write-Host "Tag / Tag: $tagName" -ForegroundColor White
Write-Host "类型 / Type: $releaseType" -ForegroundColor White
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

# 确认
$confirmation = Read-Host "确认创建此发布？/ Confirm to create this release? (y/N)"
if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
  Write-Host "❌ 已取消 / Cancelled" -ForegroundColor Yellow
  exit 0
}

# 更新 pubspec.yaml 版本号
Write-Host ""
Write-Host "📝 更新 pubspec.yaml 版本号 / Updating pubspec.yaml version number" -ForegroundColor Cyan

if (Test-Path "frontend\pubspec.yaml") {
  (Get-Content "frontend\pubspec.yaml") -replace '^version: .*', "version: ${Version}+1" | Set-Content "frontend\pubspec.yaml"
  Write-Host "✅ frontend\pubspec.yaml 已更新 / updated" -ForegroundColor Green
}

if (Test-Path "frontend\desktop\pubspec.yaml") {
  (Get-Content "frontend\desktop\pubspec.yaml") -replace '^version: .*', "version: ${Version}+1" | Set-Content "frontend\desktop\pubspec.yaml"
  Write-Host "✅ frontend\desktop\pubspec.yaml 已更新 / updated" -ForegroundColor Green
}

# 提交版本号更改
Write-Host ""
Write-Host "💾 提交版本号更改 / Committing version changes" -ForegroundColor Cyan
git add frontend\pubspec.yaml frontend\desktop\pubspec.yaml
$commitResult = git commit -m "chore: bump version to $Version" 2>&1
if ($LASTEXITCODE -eq 0) {
  Write-Host "✅ 版本号更改已提交 / Version changes committed" -ForegroundColor Green
} else {
  Write-Host "ℹ️  没有版本号更改需要提交 / No version changes to commit" -ForegroundColor Yellow
}

# 创建并推送 tag
Write-Host ""
Write-Host "🏷️  创建 tag / Creating tag: $tagName" -ForegroundColor Cyan
git tag -a "$tagName" -m "Release $tagName"

Write-Host ""
Write-Host "📤 推送 tag 到远程仓库 / Pushing tag to remote repository" -ForegroundColor Cyan
git push origin "$tagName"

Write-Host ""
Write-Host "✅ 成功！/ Success!" -ForegroundColor Green
Write-Host ""
Write-Host "🚀 GitHub Actions 将开始构建 / GitHub Actions will now start building:" -ForegroundColor Cyan
Write-Host "   - Android APK & AAB" -ForegroundColor White
Write-Host "   - Windows 可执行文件 / executable" -ForegroundColor White
Write-Host "   - Linux 二进制文件 / binary" -ForegroundColor White
Write-Host "   - macOS 应用 / application" -ForegroundColor White
Write-Host ""
Write-Host "📊 查看构建进度 / View build progress:" -ForegroundColor Cyan
$repo = git config --get remote.origin.url
if ($repo -match 'github\.com[/:](.+)\.git') {
  Write-Host "   https://github.com/$($matches[1])/actions" -ForegroundColor White
}
Write-Host ""
