---
name: /architecture
description: 架构评审工作流 - 系统性设计审查和决策
usage: /architecture <topic>
example: /architecture "Database scaling strategy for knowledge base"
---

# Architecture Review Command

收到 `/architecture` 命令时的系统性架构评审流程：

## 步骤1: 技术研究 (Architect + Backend Developer)
1. 分析需求和约束
2. 研究现有技术方案
3. 评估性能和扩展性

## 步骤2: 方案设计 (Architect Lead)
1. 生成候选方案
2. 优缺点对比
3. 风险评估
4. 推荐选择

## 步骤3: 交叉评审 (All Roles 15分钟)
1. Backend: 平台可行性
2. Frontend: API可用性
3. Test: 测试策略
4. DevOps: 运维影响

## 步骤4: 最终决策 & ADR (Architect)
1. 技术决策文档
2. 设计规范说明
3. 实施路线图
4. 回滚策略

## 输出成果
- ADR技术决策记录
- 架构图
- 性能预算
- 实施计划
