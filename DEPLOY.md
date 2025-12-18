# 部署指南

## 手动部署步骤

### 1. 环境准备
- 安装 Docker Desktop
- 确保 Docker Desktop 正在运行
- 安装 Python 3.11+ （用于本地开发）

### 2. 创建配置文件

复制示例配置文件：

```cmd
# Windows
copy backend\.env.example backend\.env

# Linux/Mac
cp backend/.env.example backend/.env
```

然后编辑 `backend\.env` 文件，修改以下关键配置：

```env
# 环境设置
ENVIRONMENT=production

# OpenAI API配置 (可选)
OPENAI_API_KEY=sk-your-actual-openai-api-key-here
OPENAI_API_BASE_URL=https://api.openai.com/v1
```

重要配置说明：
- **DATABASE_URL**: 默认使用 `MySecurePass2024!`，生产环境建议修改
- **OPENAI_API_KEY**: 如需AI功能，填入你的OpenAI API密钥
- **OPENAI_API_BASE_URL**: OpenAI API基础URL，默认为官方地址，可改为代理地址
- **ENVIRONMENT**: 生产环境使用 `production`
- **SECRET_KEY**: 由后端自动生成，无需配置

### 3. 同步Docker配置

确保 `docker\docker-compose.podcast.yml` 中的数据库密码与 `.env` 文件中的密码一致。

编辑 `docker\docker-compose.podcast.yml`，找到以下行并修改密码：

```yaml
environment:
  POSTGRES_PASSWORD: YOUR_PASSWORD  # 与.env中的密码保持一致
```

注意：两个地方的密码必须完全相同！

### 4. 启动服务

```cmd
# 进入docker目录并启动
cd docker
docker compose -f docker-compose.podcast.yml up -d

# 或者使用启动脚本
docker\start.bat
```

### 5. 检查服务状态

```cmd
# 在docker目录中运行
docker compose -f docker-compose.podcast.yml ps

# 查看日志
docker compose -f docker-compose.podcast.yml logs -f
```

### 6. 访问应用

- API 文档：http://localhost:8000/docs
- 健康检查：http://localhost:8000/health
- 交互式API：http://localhost:8000/redoc

### 7. SECRET_KEY

SECRET_KEY 会在后端首次启动时自动生成：
- 位置：`backend/data/.secret_key`
- 长度：48位
- 无需手动配置

### 8. 停止服务

```cmd
# 在docker目录中运行
docker compose -f docker-compose.podcast.yml down

# 停止并删除数据卷（⚠️ 会删除数据库数据）
docker compose -f docker-compose.podcast.yml down -v
```

### 9. 常用管理命令

```cmd
# 在docker目录中运行
docker compose -f docker-compose.podcast.yml logs backend

# 查看数据库日志
docker compose -f docker-compose.podcast.yml logs postgres

# 重启服务
docker compose -f docker-compose.podcast.yml restart

# 进入后端容器
docker exec -it podcast_backend bash

# 进入数据库
docker exec -it podcast_postgres psql -U admin -d personal_ai
```

## 文件结构

```
project-root/
├── backend/
│   ├── .env.example           # 示例配置文件
│   ├── .env                    # 实际配置文件（从.env.example复制）
│   └── data/
│       └── .secret_key        # 自动生成的密钥
├── docker/
│   ├── start.bat               # 启动脚本
│   └── docker-compose.podcast.yml
└── DEPLOY.md                   # 本文档
```

## 安全说明

- ✅ SECRET_KEY 自动生成，无需手动配置
- ✅ .secret_key 文件已加入 .gitignore
- ✅ 默认数据库密码仅适合开发/测试
- ⚠️ 生产环境请修改数据库密码

## 故障排除

### 服务无法启动
1. 检查 Docker Desktop 是否运行
2. 查看日志：`docker compose logs`
3. 确认端口 8000, 5432, 6379 未被占用

### 数据库连接失败
1. 确认 DATABASE_URL 中的密码与 docker-compose.yml 中的 POSTGRES_PASSWORD 一致
2. 检查 .env 文件是否从 .env.example 正确复制
3. 查看数据库日志：`docker compose logs postgres`

### API 访问问题
1. 等待 1-2 分钟让服务完全启动
2. 检查后端日志：`docker compose logs backend`

就这么简单！