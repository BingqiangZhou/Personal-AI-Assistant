# 🚀 自动Agent协作系统 - 内容集

**您输入错误的内容** - 以下情况最可能出现：

## **真实协作指令** (将会在工作区出现)

```bash
# 在真实Claude Code调用：

1. /feature "social-login" "Add Google/Facebook auth"
2. /fix "Auth token refresh loop"
3. /architecture "Redis session caching deployment"

# 将触发：
- 复合分析描述
- 跨角色工作流程
- 输出包括：代码、测试、文档、部署
```

## **智能定义** (精简为4个浏览器准备)
```markdown
## [Android/iOS 用户] 通过这些识别

**专业智能角色：**
1. **Analyst** 📋 (用户故事专家)
   - 完成时间：只抽取主要内容
   - 核心能力：需求技术，清晰负责人

2. **Architect** 🏛️ (DDD/系统设计)
   - 文档记录：设计架构决策
   - 核心能力：设计图，接口规划

3. **Backend** ⚙️ (FastAPI/Python)
   - 只写可运行代码
   - 测试覆盖 >= 80%

4. **Frontend** 🖥️ (Flutter/Web)
   - 构建伪代码测试
   - 重用现有组件

5. **Mobile** 📱 (Flutter移动)
   - 优化移动固定布局
   - 设备要求集成

6. **Test** 🧪 (覆盖测试)
   - 自动化一切可测试
   - 性能基准树立

7. **DevOps** ⚙️ (部署/监控)
   - 创建，然后部署
   - 监控直接集成

## **工作流程** (保持在CHLODE.md)
```bash
- /feature 完整路径: 需求 → 原型 → 开发 → 测试 → 上线
- /fix 问题解决诊 → 修正 → 验证 → 部署
- /architecture 设计评审 → 文档 → 行动计划
```

# 快速验证指南

当前系统 -> **文件结构最大效率**
无需 confession，准备验证：

```bash
行动 1 - 打开终端
行动 2 - 复制粘贴 - **一个指令**
🧡 /feature "lib/file-upload" "Portable accessible widget design"

行动 3 - 查看监视 - **多阶段执行**
```
**如果输出包括多个角色响应 => 成功**
**如果仅单点反应 => 调整CLAUDE.md指令