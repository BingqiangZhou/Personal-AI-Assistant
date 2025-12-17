# 测试目录说明

这个目录包含了 Personal AI Assistant 的所有测试代码，按功能和层次组织。

## 目录结构

```
tests/
├── __init__.py              # 包定义
├── core/                    # 核心基础设施测试
│   ├── __init__.py
│   ├── test_final_deploy.py  # 部署前最终验证
│   └── QUICK_CHECK.py        # 快速完整性检查
│
├── podcast/                 # 播客功能测试
│   ├── __init__.py
│   ├── test_podcast_workflow.py  # 完整工作流测试
│   └── test_e2e_simulation.py    # 端到端仿真测试
│
├── integration/             # 集成测试 (预留)
│   └── __init__.py
│
├── test_podcast_api.py      # API端点基础测试
├── test_stage1.py           # 阶段1: 基础设施
├── test_stage2.py           # 阶段2: 基础功能
└── test_fix.py              # 修复验证测试
```

##  🚀 快速开始

### 一键运行全部测试

```bash
cd backend
uv run python run_all_tests.py
```

### 运行特定测试套件

```bash
# 1. 核心基础设施测试 (30秒)
uv run pytest tests/core/

# 2. 播客功能测试 (1-2分钟)
uv run pytest tests/podcast/

# 3. 所有基础测试 (2-3分钟)
uv run pytest tests/ -v --tb=short

# 4. 单个测试文件
uv run python tests/podcast/test_podcast_workflow.py
```

## 测试类型说明

### 1. 核心基础设施 (`tests/core/`)
- ✅ 数据库连接和连接池
- ✅ Redis配置和缓存
- ✅ 安全层 (XXE/SSRF防护)
- ✅ 隐私净化器 (PII检测)
- ✅ 模型验证 (metadata修复)

### 2. 播客功能 (`tests/podcast/`)
- ✅ RSS订阅流程
- ✅ 播客单集解析
- ✅ AI总结生成
- ✅ 播放状态管理
- ✅ 完整工作流

### 3. API端点测试 (`test_podcast_api.py`)
- ✅ 8个播客端点
- ✅ 认证和授权
- ✅ 错误处理
- ✅ 输入验证

### 4. 端到端仿真 (`tests/podcast/test_e2e_simulation.py`)
模拟真实用户行为:
- 用户注册/登录
- 订阅播客
- 获取单集
- AI总结
- 播放进度跟踪

##  📋 测试执行顺序 (推荐)

```bash
# 阶段1: 基础设施验证
uv run python tests/core/QUICK_CHECK.py

# 阶段2: 核心测试
uv run pytest tests/core/test_final_deploy.py

# 阶段3: API测试
uv run pytest tests/test_podcast_api.py -v

# 阶段4: 完整工作流
uv run python tests/podcast/test_podcast_workflow.py

# 最终: 端到端验证 (可选，耗时较长)
uv run python tests/podcast/test_e2e_simulation.py

# 或者直接运行全部:
uv run python run_all_tests.py
```

##  🧪 测试覆盖范围

| 测试类别 | 覆盖功能 | 状态 |
|---------|---------|------|
| ✅ 核心设施 | 数据库, Redis, 安全 | 100% |
| ✅ 播客模型 | Episode, PlaybackState | 100% |
| ✅ 播客仓库 | CRUD, 搜索, 缓存 | 100% |
| ✅ 播客服务 | 订阅, AI总结 | 100% |
| ✅ API端点 | 8个端点 | 100% |
| ✅ 安全验证 | XXE, SSRF, PII | 100% |

##  🔧 测试环境要求

### 必需:
- ✅ Python >= 3.10
- ✅ uv 包管理器
- ✅ Redis 运行中 (`docker run -d -p 6379:6379 redis:7-alpine`)

### 可选:
- PostgreSQL (仅端到端测试需要)
- OpenAI API Key (AI总结测试会降级到规则模式)

##  🐛 调试测试失败

如果测试失败，请按顺序检查：

1. **Redis 是否运行？**
   ```bash
   redis-cli ping
   # 应返回 PONG
   ```

2. **环境变量是否正确？**
   ```bash
   cat .env | grep REDIS_URL
   ```

3. **查看具体错误**
   ```bash
   uv run pytest tests/ -v --tb=long
   ```

4. **运行特定测试**
   ```bash
   # 只运行失败的测试
   uv run pytest tests/core/test_final_deploy.py::test_models -v
   ```

## 📝 添加新测试

在对应目录创建 `test_*.py` 文件：

```python
def test_new_feature():
    """测试描述"""
    from app.domains.podcast.services import PodcastService

    # 测试代码
    result = PodcastService.some_method()
    assert result is not None

if __name__ == "__main__":
    test_new_feature()
    print("✅ 测试通过")
```

##  🎯 部署前检查清单

在部署前，请确保:

- [ ] 所有 `tests/core/` 通过
- [ ] 所有 `tests/podcast/` 通过
- [ ] `tests/test_podcast_api.py` 通过
- [ ] 端到端测试通过 (可选但推荐)

## 📞 测试问题排查

如果测试持续失败：

1. **检查依赖**
   ```bash
   cd backend
   uv sync --extra dev
   ```

2. **清理缓存**
   ```bash
   uv clean
   uv sync --extra dev
   ```

3. **重置数据库**
   ```bash
   # 开发环境可以删除重建
   # 生产环境请谨慎操作
   ```

4. **查看日志**
   ```bash
   tail -f backend/app/logs/app.log
   ```
