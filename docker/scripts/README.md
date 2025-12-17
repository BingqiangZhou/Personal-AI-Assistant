# 脚本说明

## start.bat - Windows一键部署脚本

### 使用方法:
1. 确保 Docker Desktop 正在运行
2. 双击 `start.bat`
3. 按照提示操作

### 脚本功能:
✅ 检查 Docker 环境
✅ 引导配置 .env 文件
✅ 自动构建和启动服务
✅ 显示服务状态
✅ 提供操作指引

---

### 如果不想要图形界面?

手动执行命令:
```powershell
# 在此目录下运行:
docker compose -f docker-compose.podcast.yml up -d --build

# 或在项目根目录运行:
docker compose -f docker/docker-compose.podcast.yml up -d --build
```

---

### 参见:
- `../README.md` - 完整部署文档
- `../部署使用指南.txt` - 中文快速指南
- `../DEPLOY_DOCKER.md` - 问题排查
