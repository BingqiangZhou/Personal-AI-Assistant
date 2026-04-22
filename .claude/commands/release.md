---
name: /release
description: 发布新版本 - 生成CHANGELOG、更新版本号、创建tag并推送
usage: /release <version>
example: /release 1.1.0
---

# Release Workflow Command

当收到 `/release <版本号>` 命令时，按以下步骤自动执行发布流程：

## 步骤1: 生成 CHANGELOG
使用 `git-cliff --tag v<版本号> -o CHANGELOG.md` 生成 CHANGELOG.md

## 步骤2: 更新版本号
1. 读取 `backend/pyproject.toml` 当前版本
2. 更新 `backend/pyproject.toml` 中的 version 为新版本号
3. 读取 `frontend/package.json` 当前版本
4. 更新 `frontend/package.json` 中的 version 为新版本号

## 步骤3: 创建提交
创建 commit，message 格式为：
```
chore(release): update version to <版本号> and generate changelog
```

## 步骤4: 推送提交
将提交推送到远程仓库

## 步骤5: 创建并推送 Tag
创建 tag（格式: v<版本号>），例如: v1.1.0
推送到远程仓库

## 示例
输入: `/release 1.1.0`
- backend 版本: 1.0.0 → 1.1.0
- frontend 版本: 1.0.0 → 1.1.0
- Tag: v1.1.0
- Commit message: `chore(release): update version to 1.1.0 and generate changelog`
