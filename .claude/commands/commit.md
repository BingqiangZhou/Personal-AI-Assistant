---
name: /commit
description: 智能分析代码更改并生成符合规范的 commit message
usage: /commit [type]
example: /commit or /commit feat
---

# Smart Commit Workflow Command

当收到 `/commit [类型]` 命令时，按以下步骤自动执行提交流程：

## 步骤1: 分析更改
1. 运行 `git status` 查看所有更改的文件
2. 运行 `git diff` 查看具体更改内容
3. 区分 staged 和 unstaged 的更改

## 步骤2: 确定 Commit 类型
根据更改内容自动推断类型（若用户未指定）：
- `test` - 测试文件改动
- `doc` - 文档改动
- `chore` - 构建、配置、依赖相关
- `feat` - 新功能（默认）
- `fix` - bug 修复
- `refactor` - 代码重构
- `style` - 代码风格调整
- `perf` - 性能优化

## 步骤3: 确定 Scope
根据文件路径推断功能模块：
- `auth` - 认证相关
- `podcast` - 播客相关
- `chat` - 聊天相关
- `settings` - 设置相关
- `user` - 用户相关
- `api` - API 相关
- `models` - 数据模型相关
- `services` - 服务层相关
- `core` - 核心功能
- `ui` - UI 组件

## 步骤4: 生成 Commit Message
格式遵循 [Conventional Commits](https://www.conventionalcommits.org/)：
```
<type>[optional scope]: <description>

[optional body]
```

## 步骤5: 等待确认
1. 显示生成的 commit message
2. 询问用户是否接受
3. 如不接受，取消操作

## 步骤6: 执行提交
1. 若有 unstaged 更改，先 `git add`
2. 执行 `git commit`
3. 显示提交结果

## Commit Message 格式参考
根据项目 `cliff.toml` 中的 commit_parsers：

| Pattern | Group |
|---------|-------|
| `^feat` | 🚀 Features |
| `^fix` | 🐛 Bug Fixes |
| `^doc` | 📚 Documentation |
| `^perf` | ⚡ Performance |
| `^refactor` | 🚜 Refactor |
| `^style` | 🎨 Styling |
| `^test` | 🧪 Testing |
| `^chore` | ⚙️ Miscellaneous Tasks |

## 示例
输入: `/commit`
- 分析更改: `frontend/lib/features/settings/...`
- 自动推断类型: `feat`
- 自动推断 scope: `settings`
- 生成: `feat(settings): add markdown rendering to update_dialog.dart, app_update_provider.dart`
- 确认后执行提交

输入: `/commit test`
- 指定类型: `test`
- 生成: `test: add tests for update_dialog markdown rendering`
