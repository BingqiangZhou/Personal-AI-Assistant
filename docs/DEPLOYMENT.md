# 🚀 播客功能部署手册

**部署工程师指南** - 完整部署流程，5分钟启动

---

## 📋 部署前检查清单

| 项目 | 要求 | 检查命令 |
|------|------|----------|
| **Python** | >=3.10 | `python --version` |
| **uv** | 已安装 | `uv --version` |
| **Docker** | 运行中 | `docker --version` |
| **PostgreSQL** | 可用 | `psql --version` |
| **端口8000** | 空闲 | `netstat -ano \| findstr :8000` |

---

## 🎯 一键部署脚本（Windows/Powershell）

```powershell
# Step 1: 启动Redis
docker run -d --name redis-podcast -p 6379:6379 redis:7-alpine

# Step 2: 进入后端目录
cd backend

# Step 3: 安装依赖（如果uv.lock不存在）
uv sync --extra dev

# Step 4: 运行测试（强烈推荐）
uv run python run_all_tests.py

# Step 5: 数据库迁移
uv run python database_migration.py

# Step 6: 配置环境变量（复制.env.example并修改）
Copy-Item .env.example .env
# 然后编辑 .env 填入数据库和密钥

# Step 7: 启动服务
uv run uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 📁 详细部署步骤

### **阶段1: 基础设施**（5分钟）

#### 1.1 启动Redis
```bash
# 方式A: Docker（推荐）
docker run -d \
  --name redis-podcast \
  --restart unless-stopped \
  -p 6379:6379 \
  redis:7-alpine

# 验证
docker ps | grep redis
redis-cli ping  # 应返回 PONG
```

#### 1.2 准备PostgreSQL
```bash
# 如果没有数据库，使用Docker快速启动
docker run -d \
  --name postgres-podcast \
  --restart unless-stopped \
  -e POSTGRES_DB=personal_ai \
  -e POSTGRES_USER=admin \
  -e POSTGRES_PASSWORD=your_secure_password \
  -p 5432:5432 \
  postgres:15-alpine
```

### **阶段2: 环境配置**（2分钟）

#### 2.1 环境变量文件
```bash
cd backend

# 复制模板
Copy-Item .env.example .env

# 编辑 .env 文件
notepad .env
```

**关键配置**：
```env
# 数据库（必需）
DATABASE_URL=postgresql+asyncpg://admin:your_secure_password@localhost:5432/personal_ai

# Redis（必需）
REDIS_URL=redis://localhost:6379

# 安全（必需）
SECRET_KEY=生成32位随机字符串：python -c "import secrets; print(secrets.token_urlsafe(32))"

# OpenAI（可选）
OPENAI_API_key=sk-...  # 如无则使用规则生成模式

# 隐私模式
LLM_CONTENT_SANITIZE_MODE=standard  # strict / standard / none
```

#### 2.2 依赖安装
```bash
# 如果uv.lock不存在
uv sync --extra dev

# 验证安装
uv run python -c "from app.core.redis import PodcastRedis; print('OK')"
```

### **阶段3: 运行测试**

**在部署前强烈建议运行所有测试：**

```bash
cd backend
# 运行完整测试套件（5-8分钟）
uv run python run_all_tests.py

# 或运行特定测试
uv run pytest tests/podcast/      # 播客功能测试
uv run pytest tests/core/         # 核心设施测试
uv run pytest tests/              # 所有测试
```

**测试完整执行的预期结果：**
```
✅ 核心基础设施测试通过
✅ 播客API端点测试通过
✅ 播客工作流测试通过
✅ 安全机制验证通过
✅ Redis配置正确
✅ 部署准备就绪
```

---

### **阶段4: 数据库准备**（3分钟）

```bash
# 方式A: 使用快速迁移脚本
cd backend
uv run python database_migration.py

# 预期输出：
# ✅ 播客相关表已创建
# ✅ 外键约束已添加
# ✅ 验证通过

# 方式B: 使用Alembic（如果已有Alembic环境）
uv run alembic upgrade head
```

**验证迁移成功**：
```bash
# 检查表是否创建
uv run python -c "
from app.core.database import engine
from sqlalchemy import inspect
import asyncio

async def check():
    async with engine.connect() as conn:
        result = await conn.execute('''
            SELECT table_name FROM information_schema.tables
            WHERE table_name LIKE 'podcast%'
        ''')
        for row in result:
            print('Table:', row[0])

asyncio.run(check())
"
```

### **阶段5: 启动服务**（3分钟）

#### 5.1 开发模式（快速启动）
```bash
cd backend
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 日志输出
# INFO: Uvicorn running on http://0.0.0.0:8000
```

#### 5.2 生产模式（推荐）
```bash
# 使用uvicorn生产参数
uv run uvicorn app.main:app \
  --host 0.0.0.0 \
  --port 8000 \
  --workers 4 \
  --log-level info

# 或使用uv的进程管理
uv run uvicorn app.main:app --env-file .env
```

#### 5.3 后台运行
```bash
# 如果使用systemd
# 创建服务文件 /etc/systemd/system/podcast-service.service

# 或使用PM2-like工具
uv run nohup uvicorn app.main:app --host 0.0.0.0 --port 8000 &
```

### **阶段6: 验证部署**（2分钟）

```bash
# 6.1 健康检查
curl http://localhost:8000/health

# 预期结果：
# {"status": "healthy"}

# 6.2 API文档访问
# 浏览器打开：http://localhost:8000/docs
# 点击 "podcasts" 标签

# 6.3 端点测试（需要登录）
# 1. 先在POSTMAN或/docs中登录获取JWT
# 2. 测试添加订阅
curl -X POST http://localhost:8000/api/v1/podcasts/subscription \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"feed_url":"https://feeds.npr.org/510289/podcast.xml"}'

# 预期结果：
# {"success": true, "subscription_id": 1, "new_episodes": 5, ...}
```

---

## 🐛 常见问题排查

### **问题1: Redis连接失败**
```
错误: Redis connection error
```
**解决**：
```bash
# 检查Redis状态
docker ps | grep redis

# 如果未启动
docker start redis-podcast

# 如果是端口冲突
docker run -d -p 6380:6379 --name redis-podcast redis:7-alpine
# 然后修改 .env: REDIS_URL=redis://localhost:6380
```

### **问题2: 数据库连接失败**
```
错误: psycopg2.OperationalError
或: cannot connect to PostgreSQL
```
**解决**：
```bash
# 检查PostgreSQL
docker ps | grep postgres

# 查看日志
docker logs postgres-podcast

# 测试连接
docker exec -it postgres-podcast psql -U admin -d personal_ai -c "SELECT 1;"

# 检查DATABASE_URL格式
# 正确: postgresql+asyncpg://user:pass@host:5432/dbname
# 错误: postgres://... (需要postgresql+asyncpg)
```

### **问题3: 迁移脚本失败**
```
错误: table already exists
```
**解决**：
```python
# 如果表已存在，忽略或删除重建
# 在config.py中设置：
# DATABASE_POOL_SIZE = 20
```

### **问题4: UV命令未找到**
```
错误: 'uv' is not recognized
```
**解决**：
```powershell
# Windows安装uv
powershell -ExecutionPolicy ByPass -c "irm https://setup.rs/install.ps1 | iex"

# 或下载二进制
# https://github.com/astral-sh/uv/releases
```

### **问题5: 端口被占用**
```
错误: Address already in use
```
**解决**：
```powershell
# 查找占用进程
netstat -ano | findstr :8000

# 终止进程
taskkill /PID <PID> /F

# 或更换端口
uv run uvicorn app.main:app --port 8001
```

---

## 📊 服务器规格建议

### **最小配置（个人使用）**
- CPU: 1核
- 内存: 1GB
- 磁盘: 10GB
- 操作系统: Linux/Windows

### **推荐配置（5-10用户）**
- CPU: 2核
- 内存: 2GB
- 磁盘: 50GB
- 操作系统: Ubuntu 20.04

### **生产配置（50+用户）**
- CPU: 4核
- 内存: 8GB
- 磁盘: 100GB SSD
- 数据库: 独立RDS实例
- Redis: 独立实例

---

## 🛡️ 安全加固（生产环境必做）

```bash
# 1. 生成强密钥
python -c "import secrets; print(secrets.token_urlsafe(64))"

# 2. 配置防火墙
# 仅允许8000端口（API）和3306（MySQL）

# 3. 设置环境变量权限
chmod 600 .env

# 4. 使用HTTPS
# 安装certbot
certbot --nginx -d your-domain.com

# 5. 限制API访问频率
# 已在代码中实现
```

---

## 📈 监控与日志

### **查看日志**
```bash
# Docker方式
docker logs -f redis-podcast
docker logs -f postgres-podcast

# 服务日志
tail -f backend/app/logs/app.log
```

### **性能监控**
```bash
# 监控Redis
redis-cli monitor

# 监控数据库连接
# 在Python中添加：
# from app.core.database import check_db_health
# 定期调用此函数
```

---

## 🎯 完整部署检查清单

### 开发阶段
- [ ] 代码格式化：`uv run black .`
- [ ] 类型检查：`uv run mypy .`
- [ ] 安全检查：`uv run python -m app.integration.podcast.security`
- [ ] 运行完整测试：`uv run python run_all_tests.py`

### 部署阶段
- [ ] Docker容器运行：Redis ✓, PostgreSQL ✓
- [ ] 环境变量配置完成
- [ ] 数据库迁移成功
- [ ] 服务启动无报错
- [ ] `/health` 返回正常
- [ ] `/docs` 可访问
- [ ] 登录API工作正常
- [ ] 添加订阅测试通过
- [ ] Redis缓存生效
- [ ] 日志记录正常

### 生产前检查
- [ ] 密钥已更换为强随机值
- [ ] 日志级别设置为 info
- [ ] 所有敏感端点已认证
- [ ] 数据库备份策略已配置

---

## 📞 部署问题求助方式

如果遇到问题，请提供：

1. **错误日志**（完整）
2. **环境变量**（隐藏密钥）
3. **Docker容器状态**：`docker ps -a`
4. **数据库连接测试**：`uv run python -c "from app.core.database import engine; print(engine)"`
5. **Redis测试**：`redis-cli ping`

---

**部署工程师可以在30分钟内完成标准部署！** 🚀

如需自动化部署脚本，请告诉我你的操作系统和环境，我可以提供特定脚本。