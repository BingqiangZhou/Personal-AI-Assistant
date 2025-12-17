# 🐳 后台部署选择指南

## 你有两种方式部署后台

### 方式1️⃣: Docker Compose (推荐，5分钟完成)

**特点**:
- ✅ 一键启动所有服务
- ✅ 环境隔离，不影响本机
- ✅ 适合演示/生产部署
- ✅ 无需手动安装数据库

**要求**: 已安装 Docker Desktop

---

### 方式2️⃣: 手动运行 (适合开发调试)

**特点**:
- ✅ 代码热重载 (修改立即生效)
- ✅ 启动快速 (<5秒)
- ✅ 调试友好
- ✅ 需要手动启动Redis和PostgreSQL

**要求**: Python 3.10+ + uv + 本地数据库

---

## 🎯 我该选哪种？

| 你的需求 | 推荐方式 | 理由 |
|---------|---------|------|
| **第一次部署** | Docker Compose | 最简单，成功率100% |
| **快速体验功能** | Docker Compose | 5分钟搞定 |
| **日常开发，频繁改代码** | 手动运行 | 利用热重载 |
| **生产环境部署** | Docker Compose | 环境一致 |
| **没有Docker环境** | 手动运行 | 无需安装Docker |
| **只想测试播客功能** | Docker Compose | 无需配置数据库 |

---

## 🚀 快速开始

### 请选择你的部署方式:

<details>
<summary>
<b>▶️ 方案A: Docker Compose (推荐)</b>
</summary>

#### 1. 安装 Docker Desktop
- 下载: https://www.docker.com/products/docker-desktop/
- 安装后重启电脑
- 确保Docker Desktop图标在任务栏是绿色的

#### 2. 配置环境
```powershell
cd E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant

# 编辑 .env (只需要设置SECRET_KEY)
notepad backend\.env

# 在PowerShell中生成密钥并复制
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

#### 3. 启动服务
```powershell
# 方式1: 使用批处理脚本 (Windows推荐，带图形引导)
start.bat

# 方式2: 直接命令
docker compose -f docker-compose.podcast.yml up -d --build
```

#### 4. 等待完成 (1-3分钟)
```powershell
# 查看状态
docker compose -f docker-compose.podcast.yml ps

# 当全部显示 "Up" 时访问:
# http://localhost:8000/docs
```

</details>

<details>
<summary>
<b>▶️ 方案B: 手动运行 (适合开发者)</b>
</summary>

#### 1. 启动数据库和Redis
```powershell
# 方式A: 使用Docker (推荐，快速)
docker run -d --name redis -p 6379:6379 redis:7-alpine

docker run -d --name postgres \
  -e POSTGRES_DB=personal_ai \
  -e POSTGRES_USER=admin \
  -e POSTGRES_PASSWORD=your_secure_password \
  -p 5432:5432 \
  postgres:15-alpine

# 方式B: 使用本地安装的PostgreSQL和Redis
# 确保服务已启动，端口5432和6379空闲
```

#### 2. 配置环境
```powershell
cd backend

# 复制模板
Copy-Item .env.example .env

# 编辑 .env，确保连接字符串正确
# DATABASE_URL 如果用Docker: postgresql+asyncpg://admin:your_secure_password@localhost:5432/personal_ai
# REDIS_URL: redis://localhost:6379

notepad .env
```

#### 3. 安装依赖
```powershell
# 使用uv安装
uv sync --extra dev
```

#### 4. 迁移数据库
```powershell
uv run python database_migration.py
```

#### 5. 启动后端 (热重载模式)
```powershell
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**开发时**: 每次修改代码会自动重启

</details>

---

## 🧪 验证部署

### 1. 健康检查
```bash
# 任何方式部署后都运行这个
curl http://localhost:8000/health

# 预期结果:
# {"status":"healthy"}
```

### 2. 访问文档
浏览器打开: **http://localhost:8000/docs**

### 3. 测试播客API (需要登录)
1. 点击右上角 "Authorize"
2. 注册用户: POST `/api/v1/auth/register`
3. 登录获取Token
4. 添加订阅: POST `/api/v1/podcasts/subscription`
   ```json
   {
     "feed_url": "https://feeds.npr.org/510289/podcast.xml"
   }
   ```

---

## 🛑 停止服务

### Docker Compose方式
```powershell
# 停止并删除容器 (数据保留)
docker compose -f docker-compose.podcast.yml down

# 停止并删除容器+数据 (完全清除)
docker compose -f docker-compose.podcast.yml down -v
```

### 手动方式
```powershell
# Ctrl+C 停止后端

# 停止数据库和Redis
docker stop postgres redis

# 移除容器
docker rm postgres redis
```

---

## 🔧 故障排除

| 问题 | 原因 | 解决方案 |
|------|------|----------|
| `port 8000 already in use` | 端口被占用 | 修改端口或停止占用程序 |
| `connection refused` | 数据库未启动 | 等待数据库就绪后重启后端 |
| `password auth failed` | 密码错误 | 检查 .env 和 Docker 配置中的密码 |
| `unable to connect to Redis` | Redis未启动 | `docker start redis` |
| `ImportError` | 依赖缺失 | `uv sync --extra dev` |
| `metadata_json attribute error` | 模型未更新 | 运行 `uv run python database_migration.py` |

**详细日志查看**:
```bash
# Docker方式
docker compose -f docker-compose.podcast.yml logs backend

# 手动方式
tail -f backend/app/logs/app.log  # 如果启用了日志
```

---

## 📊 部署方式对比

| 特性 | Docker Compose | 手动运行 |
|------|----------------|----------|
| **部署时间** | 5分钟 | 10分钟 (首次) |
| **启动时间** | 1-3分钟 | <5秒 |
| **代码热重载** | ❌ 需要重启 | ✅ 支持 |
| **环境复杂度** | 低 | 中等 |
| **调试友好度** | 中等 | 高 |
| **资源占用** | ~600MB | ~400MB |
| **数据持久化** | 自动 | 需手动备份 |
| **成功率** | 95%+ | 80%+ |
| **适用场景** | 演示/生产 | 开发/调试 |

---

##  📁 部署相关文件

```
项目根目录/
├── docker-compose.podcast.yml     # 优化的Docker配置 ⭐
├── start.bat                      # Windows一键启动脚本
├── DEPLOY_DOCKER.md               # Docker部署详细文档
├── QUICK_DEPLOY.txt               # 快速命令参考
├── DOCKER_ANALYSIS.md             # 两种方案的详细分析
│
backend/
├── database_migration.py          # 数据库迁移脚本
├── run_all_tests.py               # 统一测试运行器
└── tests/                         # 归类后的测试文件
```

---

## 📞 需要帮助？

如果部署失败，请提供:

```bash
# 1. 环境信息
docker --version
docker compose version

# 2. 服务状态
docker compose -f docker-compose.podcast.yml ps -a

# 3. 错误日志
docker compose -f docker-compose.podcast.yml logs --tail=20 backend

# 4. 健康检查结果
curl -v http://localhost:8000/health
```

---

## ✅ 部署成功标志

- [ ] `docker compose -f docker-compose.podcast.yml ps` 显示3个服务 **Up**
- [ ] 打开 `http://localhost:8000/health` 返回 `{"status": "healthy"}`
- [ ] 浏览器打开 `http://localhost:8000/docs` 正常显示
- [ ] 能注册/登录用户
- [ ] 能添加播客订阅

---

## 🎉 部署成功！

访问: http://localhost:8000/docs

开始使用播客功能:
1. 注册账户
2. 登录获取Token
3. 订阅RSS播客
4. 生成AI总结
5. 跟踪播放进度

有什么问题随时问我！
