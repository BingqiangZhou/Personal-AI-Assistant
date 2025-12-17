---
name: /fix
description: Bug自动修复工作流 - 从问题诊断到部署
usage: /fix <bug-description>
example: /fix "User authentication token refresh fails randomly"
---

# Bug Fix Workflow Command

当收到 `/fix` 命令时，按以下流程自动执行：

## 步骤1: 问题诊断 (Test Engineer + Backend Developer)
1. 复现bug
2. 分析日志和错误堆栈
3. 定位根本原因和影响范围

## 步骤2: 修复实现 (相应开发者)
1. 实现修复代码
2. 添加回归测试
3. 更新相关文档

## 步骤3: 验证测试 (Test Engineer)
1. 单元测试验证
2. 集成测试验证
3. 性能影响检查

## 步骤4: 生产部署 (DevOps Engineer)
1. 部署到staging环境
2. 运行冒烟测试
3. 部署到生产环境
4. 监控指标验证

## 输出成果
- Bug修复代码
- 测试案例
- 部署验证
- 监控确认