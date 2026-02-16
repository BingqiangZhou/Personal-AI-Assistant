---
name: /release
description: 发布新版本 - 生成CHANGELOG、更新版本号、创建tag并推送
usage: /release <version>
example: /release 1.0.0
---

# Release Workflow Command

当收到 `/release <版本号>` 命令时，按以下步骤自动执行发布流程：

## 步骤1: 生成 CHANGELOG
使用 `git-cliff --tag v<版本号> -o CHANGELOG.md`生成 CHANGELOG.md

## 步骤1.5: 更新 README.md
使用 Edit 工具直接更新 README.md 中的版本信息和日期：
1. 更新版本号徽章
2. 更新当前版本声明和日期
3. 根据需要更新功能版本注释

## 步骤2: 更新版本号
1. 读取 frontend/pubspec.yaml 当前版本
2. 更新版本号为用户提供的新版本号
3. 构建号（+后面的数字）在当前基础上加1

## 步骤3: 创建提交
创建 commit，message 格式为：
```
chore(release): update version to <版本号> and generate changelog
```

## 步骤4: 推送提交
将提交推送到远程仓库

## 步骤5: 创建并推送 Tag
创建 tag（格式: v<版本号>），例如: v1.0.0
推送到远程仓库

## 示例
输入: `/release 1.0.0`
- 当前版本: 0.1.8+21
- 新版本: 1.0.0+22
- Tag: v1.0.0
- Commit message: `chore(release): update version to 1.0.0 and generate changelog`
