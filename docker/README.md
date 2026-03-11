# Docker 部署目录

这里包含了个人AI助手播客功能的所有 Docker 部署配置文件。

---

## 🚀 快速开始

### 开发环境 (3 步搞定)

#### 1️⃣ 配置环境

```bash
# 进入 docker 目录
cd docker

# 复制并编辑开发环境配置
cp .env.dev.example .env.dev
nano .env.dev  # 或使用 notepad .env.dev (Windows)
```

#### 2️⃣ 启动服务

```bash
# 当前已在 docker 目录
docker-compose -f docker-compose.dev.yml up -d
```

#### 3️⃣ 访问服务

- Backend: http://localhost:8000
- API文档: http://localhost:8000/docs

### 生产环境部署

#### 1️⃣ 配置环境

```bash
# 进入 docker 目录
cd docker

# 复制并编辑配置文件
cp .env.example .env
nano .env  # 或使用 notepad .env (Windows)

# 必须修改的配置:
# - POSTGRES_PASSWORD: 数据库密码
# - JWT_SECRET_KEY: JWT 密钥 (用 openssl rand -hex 32 生成)
# - OPENAI_API_KEY: OpenAI API 密钥
# - DOMAIN: 你的域名 (如果有)
```

#### 2️⃣ 准备 SSL 证书

将 SSL 证书放到 `docker/nginx/cert/` 目录：
- `fullchain.pem` - 证书链
- `privkey.pem` - 私钥

#### 3️⃣ 启动服务

```bash
cd docker
docker-compose up -d
```

#### 4️⃣ 访问服务

- https://your-domain.com

---

## 环境选择 / Environment Selection

**重要**: 请根据使用场景选择正确的配置文件

| 场景 | 配置文件 | 环境变量文件 | Nginx | 用途 |
|------|----------|-------------|-------|------|
| **本地开发** | `docker-compose.dev.yml` | `docker/.env.dev` | ❌ 无 | 开发调试，直接访问后端 |
| **服务器部署** | `docker-compose.yml` | `docker/.env` | ✅ 有 | 生产环境，通过 Nginx 代理 |

### 开发环境特点

- 热重载 (代码修改自动生效)
- DEBUG 日志级别
- 暴露数据库和 Redis 端口 (方便调试)
- 单 worker 进程
- 使用 `.env.dev` 配置文件

### 生产环境特点

- 多 worker 进程 (高并发)
- INFO 日志级别
- 不暴露内部服务端口
- Nginx 反向代理 + HTTPS
- 使用 `.env` 配置文件

---

## 目录结构

```
.
├── docker/                               # Docker 目录
│   ├── docker-compose.yml                # 生产环境配置 ⭐
│   ├── docker-compose.dev.yml            # 开发环境配置 ⭐
│   ├── .env.example                      # 生产环境配置模板 ⭐
│   ├── .env                              # 实际生产环境配置
│   ├── .env.dev.example                  # 开发环境配置模板 ⭐
│   ├── .env.dev                          # 实际开发环境配置
│   ├── nginx/                            # Nginx 配置
│   │   ├── nginx.conf
│   │   ├── conf.d/
│   │   │   ├── default.conf.template     # HTTPS 模板 (自动读取环境变量)
│   │   │   └── default.conf              # HTTP 配置 (备用)
│   │   ├── cert/                         # SSL 证书目录
│   │   ├── logs/                         # Nginx 日志
│   │   ├── README.md
│   │   └── SSL_SETUP.md
│   └── README.md                         # 本文件
├── README.md                           # 本文件
├── DEPLOY_DOCKER.md                    # 详细部署指南
├── DOCKER_ANALYSIS.md                  # 技术分析文档
├── QUICK_DEPLOY.txt                    # 快速参考
├── README_DOCKER_DEPLOY.md             # 完整说明
└── 部署说明.txt                         # 中文快速指南
```

---

## 验证部署

启动成功后，检查以下服务：

### 开发环境
```bash
# 1. 查看服务状态
docker-compose -f docker-compose.dev.yml ps

# 2. 健康检查
curl http://localhost:8000/health
# 预期: {"status": "healthy"}

# 3. 访问 API 文档
# 浏览器打开: http://localhost:8000/docs
```

### 生产环境
```bash
# 1. 查看服务状态
docker-compose ps

# 2. 检查 Nginx
curl https://your-domain.com/health

# 3. 检查 SSL
curl https://your-domain.com/api/v1/health
```

---

## 资源文件说明

### 核心配置
| 文件 | 用途 | 环境 |
|------|------|------|
| `docker/.env.dev.example` | 开发环境配置模板 | 开发 |
| `docker/.env.dev` | 开发环境实际配置 | 开发 |
| `docker/.env.example` | 生产环境配置模板 | 生产 |
| `docker/.env` | 生产环境实际配置 | 生产 |
| `docker-compose.dev.yml` | 开发环境 Docker 配置 | 开发 |
| `docker-compose.yml` | 生产环境 Docker 配置 | 生产 |
| `nginx/` | Nginx 反向代理配置 | 生产 |

### 详细文档
| 文件 | 内容 |
|------|------|
| `nginx/README.md` | Nginx 使用指南 |
| `nginx/SSL_SETUP.md` | SSL 证书配置指南 |
| `README_DOCKER_DEPLOY.md` | 完整部署手册 |
| `DEPLOY_DOCKER.md` | Docker 问题排查和高级配置 |
| `DOCKER_ANALYSIS.md` | 技术分析 |

---

## 常用命令

### 开发环境

#### 启动/停止
```bash
# 启动
docker-compose -f docker-compose.dev.yml up -d

# 停止
docker-compose -f docker-compose.dev.yml down

# 重启后端
docker-compose -f docker-compose.dev.yml restart backend
```

#### 查看日志
```bash
# 所有服务日志
docker-compose -f docker-compose.dev.yml logs -f

# 仅后端日志
docker-compose -f docker-compose.dev.yml logs -f backend

# 最近20行 (用于错误排查)
docker-compose -f docker-compose.dev.yml logs --tail=20 backend
```

#### 数据管理
```bash
# 删除所有数据并重新开始
docker-compose -f docker-compose.dev.yml down -v

# 查看数据库数据
docker exec -it personal_ai_dev_postgres psql -U admin -d personal_ai_dev
```

### 生产环境

#### 启动/停止
```bash
# 启动
cd docker
docker-compose up -d

# 停止
docker-compose down

# 重启 Nginx
docker-compose restart nginx
```

#### Nginx 管理
```bash
# 测试配置
docker-compose exec nginx nginx -t

# 重新加载配置
docker-compose exec nginx nginx -s reload

# 查看 Nginx 日志
tail -f nginx/logs/access.log
tail -f nginx/logs/error.log
```

---

## 环境对比

| 特性 | 开发环境 | 生产环境 |
|------|----------|----------|
| **访问方式** | 直接访问后端 | Nginx 反向代理 |
| **端口** | 8000 | 80/443 |
| **Workers** | 1 (热重载) | 4 (无热重载) |
| **日志级别** | DEBUG | INFO |
| **数据库端口** | 暴露 5432 | 不暴露 |
| **Redis 端口** | 暴露 6379 | 不暴露 |
| **SSL/HTTPS** | 无 | 有 |
| **适用场景** | 本地开发 | 服务器部署 |

---

## 测试部署

部署完成后，运行测试验证：

```powershell
# 在容器中运行测试
docker exec -it podcast_backend uv run pytest tests/podcast/ -v

# 或运行完整测试套件
docker exec -it podcast_backend uv run python run_all_tests.py
```

---

## 问题求助

如果部署失败，请准备以下信息：

```bash
# 1. 环境检查
docker --version
docker-compose version

# 2. 服务状态 (开发环境)
docker-compose -f docker-compose.dev.yml ps -a

# 3. 错误日志
docker-compose -f docker-compose.dev.yml logs backend

# 4. 配置检查
cat .env.dev | grep -v "SECRET_KEY"
```

---

## 需要更多帮助？

- **部署指南**: 参见 `../docs/DEPLOYMENT.md`
- **Nginx 配置**: 参见 `nginx/README.md`
- **SSL 配置**: 参见 `nginx/SSL_SETUP.md`

---

## 部署成功检查清单

### 开发环境
- [ ] 配置 `docker/.env.dev`
- [ ] 服务启动: `docker-compose -f docker-compose.dev.yml ps` 显示4个服务 **Up**
- [ ] 健康检查: `curl http://localhost:8000/health` 返回健康
- [ ] 文档可访问: `http://localhost:8000/docs` 正常显示
- [ ] 功能测试: 能添加播客订阅
- [ ] 热重载测试: 修改代码后自动重启

### 生产环境
- [ ] 配置 `docker/.env` 并修改密码、域名
- [ ] 配置 SSL 证书到 `docker/nginx/cert/`
- [ ] Nginx 配置测试通过
- [ ] HTTPS 访问正常
- [ ] HTTP 自动重定向到 HTTPS

---

**祝部署顺利！🎉**

---

## Celery Runtime Checklist (2026-03)

For hourly feed refresh + backlog transcription + summary compensation, ensure all three services are running:

- `celery_worker_core` (queues: `subscription_sync,ai_generation,maintenance`)
- `celery_worker_transcription` (queue: `transcription`)
- `celery_beat`

Quick verification:

```bash
cd docker
docker-compose ps
```
