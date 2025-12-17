#  Docker 部署目录

这里包含了个人AI助手播客功能的所有 Docker 部署配置文件。

---

##  目录结构

```
docker/
├── docker-compose.podcast.yml          # 核心配置文件 (⭐ 使用这个)
├── README.md                            # 本文件
├── DEPLOY_DOCKER.md                     # 详细部署指南
├── DOCKER_ANALYSIS.md                   # 技术分析文档
├── QUICK_DEPLOY.txt                     # 快速参考
├── README_DOCKER_DEPLOY.md              # 完整说明
├── 部署说明.txt                         # 中文快速指南
└── scripts/
    └── start.bat                        # Windows 一键启动
```

---

##  快速开始 (3步搞定)

### 1️⃣ 配置环境
```powershell
cd E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant\docker

# 复制配置到父级的 backend 目录
copy ..\backend\.env.example ..\backend\.env

# 编辑配置文件
notepad ..\backend\.env

# 至少设置以下两项:
# SECRET_KEY=生成一个强密钥: python -c "import secrets; print(secrets.token_urlsafe(48))"
# DATABASE_URL=postgresql+asyncpg://admin:你的密码@postgres:5432/personal_ai
```

### 2️⃣ Windows 用户 (最简单)
```powershell
# 在 docker 目录下双击运行
scripts\start.bat
```

### 3️⃣ 或者命令行启动
```powershell
# 从项目根目录运行
docker compose -f docker/docker-compose.podcast.yml up -d --build
```

---

## 📊 验证部署

启动成功后，检查以下服务：

```bash
# 1. 查看服务状态
docker compose -f docker/docker-compose.podcast.yml ps

# 2. 健康检查
curl http://localhost:8000/health
# 预期: {"status": "healthy"}

# 3. 访问 API 文档
# 浏览器打开: http://localhost:8000/docs
```

---

## 📝 资源文件说明

### 核心配置
| 文件 | 用途 | 优先级 |
|------|------|--------|
| `docker-compose.podcast.yml` | Docker Compose 配置 | ⭐ 必须使用 |
| `scripts/start.bat` | Windows 一键启动脚本 | ⭐ 推荐 |
| `部署说明.txt` | 中文快速指南 | ⭐ 推荐 |

### 详细文档
| 文件 | 内容 |
|------|------|
| `README_DOCKER_DEPLOY.md` | 完整部署手册 (两种方式对比) |
| `DEPLOY_DOCKER.md` | Docker 问题排查和高级配置 |
| `DOCKER_ANALYSIS.md` | 技术分析 (为什么推荐此配置) |
| `QUICK_DEPLOY.txt` | 极简命令清单 |

---

##  🚫 如果不使用 Docker？

手动运行 (开发模式):
```powershell
# 1. 启动数据库 (需要单独安装 Postgres 和 Redis)
# 2. 编辑 backend/.env，修改为 localhost
# 3. 后台运行:
cd backend
uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

---

##  🛑 常用命令

### 启动/停止
```powershell
# 启动
docker compose -f docker/docker-compose.podcast.yml up -d

# 停止
docker compose -f docker/docker-compose.podcast.yml down

# 重启后端
docker compose -f docker/docker-compose.podcast.yml restart backend
```

### 查看日志
```powershell
# 所有服务日志
docker compose -f docker/docker-compose.podcast.yml logs -f

# 仅后端日志
docker compose -f docker/docker-compose.podcast.yml logs -f backend

# 最近20行 (用于错误排查)
docker compose -f docker/docker-compose.podcast.yml logs --tail=20 backend
```

### 数据管理
```powershell
# 删除所有数据并重新开始
docker compose -f docker/docker-compose.podcast.yml down -v

# 查看数据库数据
docker exec -it podcast_postgres psql -U admin -d personal_ai
```

---

##  ⚙️ docker-compose.podcast.yml 优化说明

为什么比原版 `docker-compose.yml` 更好:

### ✅ 修复的问题
1. **数据库名称**：`personal_ai` (匹配代码)
2. **用户密码**：`admin` / 自定义 (匹配 .env.example)
3. **环境变量**：使用 Docker 网络名称 (非 localhost)
4. **Celery**：已移除 (当前代码未实现)
5. **健康检查**：自动等待数据库就绪
6. **自动迁移**：启动时自动运行数据库迁移

### ✅ 特性
- **服务数量**：3个 (PostgreSQL, Redis, Backend) → 快速启动
- **数据持久化**：所有数据自动保存
- **自动重启**：容器崩溃自动恢复
- **健康检查**：确保启动顺序正确
- **单Redis DB**：适合个人使用

---

##  🧪 测试部署

部署完成后，运行测试验证：

```powershell
# 在容器中运行测试
docker exec -it podcast_backend uv run pytest tests/podcast/ -v

# 或运行完整测试套件
docker exec -it podcast_backend uv run python run_all_tests.py
```

---

##  🆘 问题求助

如果部署失败，请准备以下信息：

```powershell
# 1. 环境检查
docker --version
docker compose version

# 2. 服务状态
docker compose -f docker/docker-compose.podcast.yml ps -a

# 3. 错误日志
docker compose -f docker/docker-compose.podcast.yml logs backend

# 4. 父级 .env 配置
cat ../backend/.env | grep -v "SECRET_KEY"
```

---

## 📞 需要更多帮助？

- **详细部署**: 查看 `README_DOCKER_DEPLOY.md`
- **问题排查**: 查看 `DEPLOY_DOCKER.md`
- **技术原理**: 查看 `DOCKER_ANALYSIS.md`
- **快速命令**: 查看 `QUICK_DEPLOY.txt`
- **中文指南**: 查看 `部署说明.txt`

---

## ✅ 部署成功检查清单

- [ ] 服务启动: `docker compose ... ps` 显示3个服务 **Up**
- [ ] 健康检查: `curl http://localhost:8000/health` 返回健康
- [ ] 文档可访问: `http://localhost:8000/docs` 正常显示
- [ ] 功能测试: 能添加播客订阅

---

**祝部署顺利！🎉**

需要更详细的帮助，查看对应文档即可。
