# 🐳 Docker-Compose 一键部署指南

**推荐部署方式** - 5分钟完成完整环境搭建 ✨

---

## 📋 部署前要求

| 项目 | 要求 | 检查命令 |
|------|------|----------|
| **Docker Desktop** | 已安装并运行 | `docker --version` |
| **Docker Compose** | v2.x 或 v1.29+ | `docker compose version` 或 `docker-compose --version` |

---

##  一键部署 (Windows)

### 步骤1: 准备环境 (1分钟)

```powershell
cd E:\Projects\AI\PersonalKnowledgeLibrary\Claude\personal-ai-assistant

# 修改配置文件 (必须!)
notepad backend\.env
# 复制以下内容并保存:

# ========================================
# 生产环境配置
SECRET_KEY=使用下面的命令生成一个强密钥
ENVIRONMENT=Docker

# 数据库配置 (Docker自动连接)
DATABASE_URL=postgresql+asyncpg://admin:your_secure_password@postgres:5432/personal_ai

# Redis配置 (Docker自动连接)
REDIS_URL=redis://redis:6379

# API配置
ALLOWED_HOSTS=["*"]
API_V1_STR=/api/v1

# 播客配置 (可选)
# OPENAI_API_KEY=sk-...  # 如果没有会自动降级到规则模式
LLM_CONTENT_SANITIZE_MODE=standard
# ========================================
```

```powershell
# 生成强密钥 (PowerShell)
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"

# 示例输出:
# SECRET_KEY=uG8x9z...复制这个值到.env
```

### 步骤2: 一键启动 (2分钟)

```powershell
# 方式A: 使用优化的播客配置 (推荐)
docker compose -f docker-compose.podcast.yml up -d

# 方式B: 使用原始配置 (如果你想测试原完整系统)
docker compose up -d

# 如果使用Docker compose v1:
# docker-compose -f docker-compose.podcast.yml up -d
```

**首次启动会下载镜像并启动服务，需要等待 2-3 分钟**

### 步骤3: 等待启动完成 (1分钟)

```powershell
# 查看服务状态 (只会显示运行中的容器)
docker compose -f docker-compose.podcast.yml ps

# 查看详细日志 (按Ctrl+C退出)
docker compose -f docker-compose.podcast.yml logs -f --tail=20

# 等待出现类似:
# podcast_backend    | INFO:     Uvicorn running on http://0.0.0.0:8000
# podcast_backend    | INFO:     Application startup complete.
```

### 步骤4: 验证部署 (30秒)

```powershell
# 1. 健康检查 - 应返回 {"status": "healthy"}
curl http://localhost:8000/health

# 2. 访问文档
# 请在浏览器中打开: http://localhost:8000/docs
```

---

##  🎯 Docker部署后的命令

### 查看服务状态
```powershell
docker compose -f docker-compose.podcast.yml ps
```

**预期输出:**
```
NAME                 COMMAND                  STATUS          PORTS
podcast_postgres     "docker-entrypoint.s…"   Up 2 minutes    0.0.0.0:5432->5432/tcp
podcast_redis        "redis-server --appe…"   Up 2 minutes    0.0.0.0:6379->6379/tcp
podcast_backend      "uvicorn app.main:app…"   Up 2 minutes    0.0.0.0:8000->8000/tcp
```

### 查看日志
```powershell
# 后端日志
docker compose -f docker-compose.podcast.yml logs backend

# 实时日志
docker compose -f docker-compose.podcast.yml logs -f backend
```

### 停止服务
```powershell
# 停止并删除容器
docker compose -f docker-compose.podcast.yml down

# 停止但保留数据
docker compose -f docker-compose.podcast.yml stop
```

### 重启服务
```powershell
# 重启后端 (代码更新后)
docker compose -f docker-compose.podcast.yml restart backend

# 重启所有服务
docker compose -f docker-compose.podcast.yml restart
```

---

##  🧪 Docker部署测试

### 1. 快速功能测试
```powershell
# 运行测试 (使用Docker容器)
docker exec -it podcast_backend uv run pytest tests/podcast/test_podcast_api.py -v
```

### 2. 端到端测试
```powershell
# 1. 打开浏览器访问 http://localhost:8000/docs
# 2. 尝试以下操作:
#    a. POST /api/v1/auth/register - 注册用户
#    b. POST /api/v1/auth/login - 登录获取token
#    c. 点击"Authorize"按钮，输入Bearer token
#    d. POST /api/v1/podcasts/subscription - 添加播客订阅
#    e. GET /api/v1/podcasts/episodes - 查看单集列表
#    f. POST /api/v1/podcasts/{id}/summary - 生成AI总结
```

---

##  🛠️ 常见问题 Docker部署

### **问题1: 端口冲突**
```
Error: Bind for 0.0.0.0:8000 failed: port is already allocated
```

**解决:**
```powershell
# 检查占用的进程
netstat -ano | findstr :8000

# 方法A: 停止冲突的服务
taskkill /PID <PID> /F

# 方法B: 修改端口映射
# 编辑 docker-compose.podcast.yml
# 修改行: - "8000:8000" 为 - "8001:8000"
# 访问 http://localhost:8001/docs
```

### **问题2: 容器启动失败**
```powershell
# 查看具体错误
docker compose -f docker-compose.podcast.yml logs backend

# 常见原因:
# 1. 环境变量配置错误 -> 检查 .env 文件
# 2. 镜像构建失败 -> 检查 backend/Dockerfile
```

### **问题3: 数据库连接失败**
```
psycopg2.OperationalError: connection failed
```

**解决:**
```powershell
# 1. 检查PostgreSQL日志
docker logs podcast_postgres

# 2. 如果是密码问题，修改 .env 并重启
# 3. 删除所有数据重新启动 (会丢失数据)
docker compose -f docker-compose.podcast.yml down -v
docker compose -f docker-compose.podcast.yml up -d
```

### **问题4: 无法连接数据库容器**
```
连接超时: could not connect to server
```

**检查:**
```powershell
# 1. 检查PostgreSQL是否完全启动
docker exec -it podcast_postgres pg_isready -U admin

# 2. 等待PostgreSQL完成初始化
docker logs podcast_postgres --tail=20

# 3. 在backend日志中看连接尝试
docker logs podcast_backend --tail=20
```

### **问题5: 首次启动很慢**
```powershell
# Docker第一次需要下载镜像，耐心等待
# 你可以查看下载进度:
docker compose -f docker-compose.podcast.yml pull

# 或者查看Docker Desktop界面的镜像标签页
```

---

##  📊 资源占用预估

| 服务 | CPU | 内存 | 磁盘 |
|------|-----|------|------|
| PostgreSQL | < 5% | 200MB | 100MB+ |
| Redis | < 2% | 50MB | 10MB |
| Backend | 10-20% | 300MB | 200MB |
| **总计** | < 30% | **~600MB** | **~600MB+** |

**推荐配置**: 2核CPU + 2GB内存 + 10GB磁盘

---

##  🔧 高级配置

### 自定义网络
```yml
# docker-compose.podcast.yml 第100行
networks:
  podcast_network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16  # 自定义子网
```

### 数据持久化位置
```powershell
# Windows默认位置
C:\Users\<your-username>\AppData\Local\Docker\volume

# 如果要更改挂载路径，编辑 docker-compose.podcast.yml
volumes:
  - postgres_data:/var/lib/postgresql/data  # 数据库存储
  - redis_data:/data                          # Redis持久化
  - ./backend:/app                            # 代码目录
```

---

##  🎯 部署成功验证

✅ **服务启动检查清单:**

- [ ] `docker compose -f docker-compose.podcast.yml ps` 显示3个服务都运行
- [ ] `curl http://localhost:8000/health` 返回 `{"status": "healthy"}`
- [ ] 浏览器访问 `http://localhost:8000/docs` 正常显示
- [ ] 能正常注册/登录用户
- [ ] 能添加播客订阅
- [ ] 能获取播客单集

---

##  📦 生产环境调整建议

如果部署到生产环境，请修改:

1. **密码安全**: 所有密码使用强随机值
2. **HTTPS**: 使用反向代理(Nginx/Caddy) + SSL证书
3. **资源限制**: 在docker-compose中添加:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '1'
         memory: 512M
   ```
4. **日志轮转**: 配置Docker日志驱动
5. **备份**: 定期备份PostgreSQL数据卷

---

##  🆘 寻求帮助

如果部署遇到问题，请提供:

```bash
# 1. 运行环境
docker --version
docker compose version

# 2. 服务状态
docker compose -f docker-compose.podcast.yml ps -a

# 3. 详细日志
docker compose -f docker-compose.podcast.yml logs --tail=50

# 4. 健康检查
curl -v http://localhost:8000/health
```

**部署文档版本**: v1.0 (支持Podcast功能)
**上次更新**: 2025-12-17
