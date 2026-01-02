# Playwright Browser Fallback - Quick Start Guide

## 快速开始 (Quick Start)

### 1. 构建并启动服务 (Build and Start Services)

```bash
cd docker
docker-compose up -d
```

**预计时间**:
- 首次构建: 5-10 分钟（下载 Chromium ~300MB）
- 后续启动: 30-60 秒

**Estimated time**:
- First build: 5-10 minutes (download Chromium ~300MB)
- Subsequent starts: 30-60 seconds

### 2. 验证安装 (Verify Installation)

```bash
# 进入 backend 容器
docker-compose exec backend bash

# 运行验证脚本
bash /app/docker/verify-playwright.sh

# 或者手动测试
python -c "from playwright.sync_api import sync_playwright; print('Playwright OK')"
```

### 3. 查看日志 (View Logs)

```bash
# 查看所有服务日志
docker-compose logs -f

# 只查看 backend 和 celery worker
docker-compose logs -f backend celery_worker

# 过滤 Playwright 相关日志
docker-compose logs backend | grep -i "browser\|playwright\|fallback"
```

### 4. 测试浏览器下载 (Test Browser Download)

触发一个播客转录任务，系统会自动使用浏览器回退（如果需要）：

```bash
# API 调用示例
curl -X POST http://localhost:8000/api/v1/podcast/episodes/{episode_id}/transcribe \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

## 常用命令 (Common Commands)

### Docker 操作

```bash
# 构建镜像
docker-compose build backend

# 重新构建（无缓存）
docker-compose build --no-cache backend

# 启动服务
docker-compose up -d

# 停止服务
docker-compose down

# 查看服务状态
docker-compose ps

# 查看资源使用
docker stats
```

### 调试命令

```bash
# 查看容器详细信息
docker-compose exec backend env | grep PLAYWRIGHT

# 检查共享内存
docker-compose exec backend df -h /dev/shm

# 检查内存使用
docker-compose exec backend free -h

# 进入容器 shell
docker-compose exec backend bash
docker-compose exec celery_worker bash
```

## 日志关键词 (Log Keywords)

### 成功的浏览器下载 (Successful Browser Download)

```
🌐 [BROWSER DOWNLOAD] Starting browser download
✅ [BROWSER DOWNLOAD] Successfully downloaded
✅ [FALLBACK] Browser fallback download succeeded
download_method: "browser"
```

### 回退触发 (Fallback Triggered)

```
⚠️ [FALLBACK] aiohttp download failed
🌐 [FALLBACK] Triggering browser fallback download
```

### 错误情况 (Error Cases)

```
❌ [BROWSER DOWNLOAD] Playwright error
❌ [FALLBACK] Both aiohttp and browser downloads failed
```

## 性能监控 (Performance Monitoring)

### 实时监控

```bash
# 实时查看容器资源使用
docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}"

# 查看特定服务日志
docker-compose logs -f --tail=100 backend | grep -E "BROWSER|FALLBACK|download"
```

### 关键指标 (Key Metrics)

- **下载方法分布**: `aiohttp` vs `browser`
- **回退触发率**: 浏览器下载占比
- **下载时间**: 各方法平均耗时
- **内存使用**: 容器内存占用
- **CPU 使用**: 浏览器运行时 CPU 峰值

## 故障排查速查表 (Troubleshooting Quick Reference)

| 问题 (Problem) | 检查 (Check) | 解决方案 (Solution) |
|----------------|--------------|---------------------|
| 容器启动失败 | `docker-compose logs backend` | 检查磁盘空间，重新构建 |
| 浏览器下载失败 | `playwright install chromium` | 重新安装浏览器 |
| OOM 错误 | `docker stats` | 增加 memory 限制 |
| Chromium 崩溃 | `df -h /dev/shm` | 增加 shm_size |
| 下载速度慢 | 网络连接 | 调整 timeout 参数 |

## 配置调整 (Configuration Tuning)

### 增加资源限制

编辑 `docker-compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '4.0'      # 增加 CPU
      memory: 4G       # 增加内存
    shm_size: 4gb      # 增加共享内存
```

### 调整并发数

在代码中调整:

```python
browser_downloader = BrowserAudioDownloader(
    timeout=300,
    max_concurrent=5  # 增加并发浏览器实例
)
```

### 调整超时时间

```python
downloader = AudioDownloader(
    timeout=600,  # 10 分钟超时
    chunk_size=16384
)
```

## 相关文件 (Related Files)

- `backend/Dockerfile` - Docker 镜像构建
- `docker/docker-compose.yml` - 服务编排配置
- `backend/app/domains/podcast/transcription.py` - 浏览器下载实现
- `docker/PLAYWRIGHT_SETUP.md` - 完整文档

## 获取帮助 (Get Help)

1. 查看详细文档: `docker/PLAYWRIGHT_SETUP.md`
2. 检查日志: `docker-compose logs backend | tail -100`
3. 运行验证: `bash docker/verify-playwright.sh`
4. 查看测试: `backend/app/domains/podcast/tests/`

---

**快速验证清单** (Quick Verification Checklist):

- [ ] Docker 镜像构建成功
- [ ] 容器正常启动
- [ ] Playwright 命令可用
- [ ] Chromium 浏览器已安装
- [ ] 共享内存配置正确 (>= 1GB)
- [ ] 日志中无严重错误
- [ ] 可以触发转录任务

**最后更新** (Last Updated): 2026-01-03
