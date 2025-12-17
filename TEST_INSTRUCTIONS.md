# 🧪 播客功能测试说明

## 当前状态

所有依赖和代码已准备就绪。**但需要在用户环境运行测试**，因为我无法直接执行uv命令。

---

## 如何运行测试

### 第一步：安装依赖（使用uv）

```bash
cd backend

# 方法1: 如果已有uv.lock
uv sync --extra dev

# 方法2: 如果没有uv.lock，从pyproject.toml安装
uv pip install -r pyproject.toml

# 方法3: 如果希望快速验证现有环境
uv pip install defusedxml aiohttp phonenumbers email-validator redis beautifulsoup4
```

### 第二步：运行测试脚本

```bash
cd backend
uv run python test_podcast_workflow.py
```

### 预期输出

**如果一切正常，将看到：**
```
============================================================
PODCAST FEATURE INTEGRITY CHECK
============================================================
TEST: Security module...
   [PASS] Security module OK
TEST: Redis configuration...
   Redis URL: redis://localhost:6379
   [PASS] Redis OK
TEST: Database models...
   [PASS] Models OK
TEST: Services layer...
   [PASS] Services OK
TEST: API routing...
   [PASS] API OK

TEST: Full workflow integration...
   [PASS] podcast_episodes table exists (如果已迁移)
   [PASS] PodcastPlaybackState table exists
   [PASS] Workflow base OK

============================================================

[PASS] ALL (6/6) ✓

Next steps:
1. python database_migration.py
2. uvicorn app.main:app --reload
3. http://localhost:8000/docs
```

---

## 失败排查

### 1. 模块导入失败
**错误**: `No module named 'defusedxml'`
**解决**: 运行 `uv pip install defusedxml aiohttp phonenumbers phonenumbers`

### 2. 语法错误
**错误**: `SyntaxError: f-string expression`
**解决**: 文件已修复，检查是否使用了旧版本

### 3. 数据库连接错误
**错误**: `psycopg2` 或 `asyncpg` 相关错误
**解决**:
```bash
# 检查PostgreSQL是否运行
docker ps | grep postgres

# 如果没有，启动
docker-compose up -d postgres
```

### 4. Redis连接失败
**错误**: `Redis connection error`
**解决**:
```bash
# 检查Redis
docker ps | grep redis

# 启动
docker-compose up -d redis
```

---

## 完整验证流程

### 验证依赖状态
```bash
uv run python -c "from defusedxml import ElementTree; print('XXE防护 OK')"
uv run python -c "from app.core.llm_privacy import ContentSanitizer; print('隐私净化 OK')"
uv run python -c "from app.domains.podcast.models import PodcastEpisode; print('模型 OK')"
```

### 验证数据库迁移
```bash
uv run python database_migration.py
```

### 验证API端点
```bash
uv run uvicorn app.main:app --reload --port 8000
# 然后访问 http://localhost:8000/docs 查看 /podcasts 端点
```

---

## 所有关键文件位置

```
backend/
├── app/
│   ├── core/
│   │   ├── config.py              # ✅ 数据库池优化配置
│   │   ├── llm_privacy.py         # ✅ 隐私净化器
│   │   └── redis.py               # ✅ Redis管理器
│   ├── domains/
│   │   └── podcast/
│   │       ├── models.py          # ✅ 播客数据模型
│   │       ├── repositories.py    # ✅ 数据访问
│   │       ├── services.py        # ✅ 业务逻辑
│   │       └── api/
│   │           ├── routes.py      # ✅ API端点
│   │           └── __init__.py
│   ├── integration/
│   │   └── podcast/
│   │       ├── security.py        # ✅ XXE/SSRF防护
│   │       └── secure_rss_parser.py
│   └── main.py                    # ✅ 已添加播客路由
├── database_migration.py          # ✅ 迁移脚本
├── test_podcast_workflow.py       # ✅ 测试脚本
├── requirements.txt               # ❌ 已废弃 (用uv)
├── pyproject.toml                 # ✅ 新版依赖配置
└── uv.lock                        # (运行uv sync后生成)
```

---

## 核心功能完成度检查

- ✅ **安全修复**: XXE防护 + PII过滤 + 池优化
- ✅ **数据模型**: PodcastEpisode + PlaybackState
- ✅ **存储层**: Repository with async支持
- ✅ **业务层**: Service with LLM总结
- ✅ **API层**: 7个完整端点
- ✅ **Redis简化**: 单数据库设计
- ✅ **文档更新**: CLAUDE.md + 角色文档

---

## 下一步（通过测试后）

### 1. 快速验证工作流
```bash
# 注册用户 (假设使用现有auth)
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'

# 添加播客
curl -X POST http://localhost:8000/api/v1/podcasts/subscription \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"feed_url":"https://feeds.npr.org/510289/podcast.xml"}'
```

### 2. 运行完整端到端测试
```bash
# 创建测试脚本
uv run python end_to_end_test.py
```

---

**需要帮助吗？分享测试输出，我来诊断问题！**