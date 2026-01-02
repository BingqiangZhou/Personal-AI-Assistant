# Playwright + Chromium 浏览器下载回退功能

## 概述 (Overview)

本项目已集成 Playwright 浏览器下载功能，用于在常规 HTTP 下载失败时（如遇到 403、429、503 等错误）自动切换到浏览器下载模式。这对于处理有 CDN 防护或访问限制的音频文件非常有用。

The project has integrated Playwright browser download functionality to automatically fall back to browser-based downloading when regular HTTP downloads fail (e.g., 403, 429, 503 errors). This is particularly useful for handling audio files with CDN protection or access restrictions.

## 功能特性 (Features)

### 自动回退机制 (Automatic Fallback Mechanism)

音频下载流程：

1. **首选方法**: 使用 `aiohttp` 进行 HTTP 下载（快速、高效）
2. **自动回退**: 当遇到以下错误时，自动切换到浏览器下载：
   - HTTP 403 (禁止访问)
   - HTTP 429 (请求过多)
   - HTTP 503 (服务不可用)
   - 连接超时
   - SSL 证书错误

Audio download flow:

1. **Primary method**: Use `aiohttp` for HTTP download (fast, efficient)
2. **Automatic fallback**: When encountering the following errors, automatically switch to browser download:
   - HTTP 403 (Forbidden)
   - HTTP 429 (Too Many Requests)
   - HTTP 503 (Service Unavailable)
   - Connection timeout
   - SSL certificate errors

### 技术实现 (Technical Implementation)

- **浏览器引擎**: Chromium (headless mode)
- **自动化框架**: Playwright for Python
- **运行模式**: 无头模式 (headless)，适合服务器环境
- **并发控制**: 支持多个浏览器实例并发下载
- **资源管理**: 自动清理浏览器资源，防止内存泄漏

- **Browser engine**: Chromium (headless mode)
- **Automation framework**: Playwright for Python
- **Run mode**: Headless mode, suitable for server environments
- **Concurrency control**: Supports multiple concurrent browser instances
- **Resource management**: Automatic cleanup of browser resources to prevent memory leaks

## Docker 配置 (Docker Configuration)

### 更新内容 (Updates)

#### 1. Dockerfile 更新

添加了 Playwright 系统依赖和浏览器安装：

Added Playwright system dependencies and browser installation:

```dockerfile
# Install Playwright system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        libpq-dev \
        curl \
        ffmpeg \
        # Playwright and Chromium dependencies
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libdbus-1-3 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Install Playwright Chromium browser
RUN playwright install chromium
RUN playwright install-deps chromium
```

#### 2. docker-compose.yml 更新

为 Backend 和 Celery Worker 服务配置了资源限制和共享内存：

Configured resource limits and shared memory for Backend and Celery Worker services:

```yaml
backend:
  environment:
    - PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 2G
      reservations:
        cpus: '0.5'
        memory: 512M
  shm_size: 2gb  # Required for Chromium

celery_worker:
  environment:
    - PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 2G
      reservations:
        cpus: '0.5'
        memory: 512M
  shm_size: 2gb  # Required for Chromium
```

### 资源要求 (Resource Requirements)

| 服务 (Service) | CPU 限制 (CPU Limit) | 内存限制 (Memory Limit) | 共享内存 (Shared Memory) |
|----------------|---------------------|-------------------------|--------------------------|
| backend        | 2.0 cores           | 2GB                     | 2GB                      |
| celery_worker  | 2.0 cores           | 2GB                     | 2GB                      |

**注意**: Chromium 浏览器需要足够的共享内存 (`/dev/shm`) 来运行。如果遇到浏览器崩溃问题，可以增加 `shm_size`。

**Note**: Chromium browser requires sufficient shared memory (`/dev/shm`) to run. If you encounter browser crashes, you can increase the `shm_size`.

## 使用方法 (Usage)

### 1. 构建 Docker 镜像 (Build Docker Image)

```bash
cd docker
docker-compose build
```

首次构建会下载并安装 Chromium 浏览器（约 300MB），可能需要几分钟时间。

First-time build will download and install Chromium browser (~300MB), which may take a few minutes.

### 2. 启动服务 (Start Services)

```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f backend celery_worker
```

### 3. 验证浏览器安装 (Verify Browser Installation)

```bash
# 进入 backend 容器
docker-compose exec backend bash

# 检查 Playwright 浏览器
playwright install --help

# 退出容器
exit
```

### 4. 测试浏览器下载功能 (Test Browser Download)

触发一个播客音频转录任务，系统会自动使用浏览器回退下载（如果常规下载失败）：

Trigger a podcast audio transcription task, the system will automatically use browser fallback download (if regular download fails):

```bash
# 通过 API 触发转录任务
curl -X POST http://localhost:8000/api/v1/podcast/episodes/{episode_id}/transcribe \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 工作原理 (How It Works)

### 下载流程 (Download Flow)

```
┌─────────────────────────────────────────────────────────────┐
│                    音频下载请求                              │
│                  Audio Download Request                     │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
            ┌──────────────────────┐
            │  aiohttp 下载尝试    │
            │  Try aiohttp download │
            └──────────┬───────────┘
                       │
           ┌───────────┴───────────┐
           │                       │
           ▼                       ▼
    ┌─────────────┐         ┌─────────────┐
    │   成功      │         │   失败      │
    │  Success    │         │   Failed    │
    └──────┬──────┘         └──────┬──────┘
           │                       │
           │                       ▼
           │            ┌────────────────────┐
           │            │  检查错误类型       │
           │            │  Check error type  │
           │            └──────────┬─────────┘
           │                       │
           │           ┌───────────┴───────────┐
           │           │                       │
           │           ▼                       ▼
           │    ┌─────────────┐         ┌─────────────┐
           │    │ 可回退错误  │         │ 不可回退    │
           │    │ Fallback    │         │ No fallback │
           │    └──────┬──────┘         └──────┬──────┘
           │           │                       │
           │           ▼                       ▼
           │    ┌─────────────┐         ┌─────────────┐
           │    │Playwright   │         │   抛出异常  │
           │    │Browser DL   │         │  Raise error │
           │    └──────┬──────┘         └─────────────┘
           │           │
           └───────────┼───────────────────┐
                       │                   │
                       ▼                   ▼
                ┌─────────────┐     ┌─────────────┐
                │  返回结果   │     │  返回结果   │
                │ Return result│     │ Return result│
                └─────────────┘     └─────────────┘
```

### 日志输出 (Log Output)

系统会记录详细的下载方法信息：

The system logs detailed download method information:

```
# 常规下载成功
✅ [FALLBACK] aiohttp download succeeded
download_method: "aiohttp"

# 浏览器回退下载
⚠️ [FALLBACK] aiohttp download failed: HTTP 403
🌐 [FALLBACK] Triggering browser fallback download...
✅ [FALLBACK] Browser fallback download succeeded
download_method: "browser"
```

## 代码示例 (Code Examples)

### 触发回退下载 (Trigger Fallback Download)

```python
from app.domains.podcast.transcription import AudioDownloader

async def download_audio_with_fallback(url: str, destination: str):
    """
    带自动回退的音频下载
    Audio download with automatic fallback
    """
    async with AudioDownloader() as downloader:
        file_path, file_size, method = await downloader.download_file_with_fallback(
            url=url,
            destination=destination
        )

        print(f"下载完成！方法: {method}, 大小: {file_size} bytes")
        print(f"Download complete! Method: {method}, Size: {file_size} bytes")

        return file_path, file_size, method
```

### 直接使用浏览器下载 (Direct Browser Download)

```python
from app.domains.podcast.transcription import BrowserAudioDownloader

async def download_with_browser(url: str, destination: str):
    """
    直接使用 Playwright 浏览器下载
    Direct download using Playwright browser
    """
    browser_downloader = BrowserAudioDownloader(timeout=300)

    file_path, file_size = await browser_downloader.download_with_playwright(
        url=url,
        destination=destination
    )

    print(f"浏览器下载完成！大小: {file_size} bytes")
    print(f"Browser download complete! Size: {file_size} bytes")

    return file_path, file_size
```

## 性能优化建议 (Performance Optimization)

### 1. 并发控制 (Concurrency Control)

```python
# BrowserAudioDownloader 默认最大并发数为 3
# 可以根据服务器资源调整

browser_downloader = BrowserAudioDownloader(
    timeout=300,
    max_concurrent=5  # 增加并发数
)
```

### 2. 超时设置 (Timeout Configuration)

```python
# 根据网络状况调整超时时间
# 默认: 300 秒 (5 分钟)

downloader = AudioDownloader(
    timeout=600,  # 10 分钟超时
    chunk_size=16384  # 增大块大小
)
```

### 3. 资源限制 (Resource Limits)

如果服务器资源有限，可以降低 docker-compose.yml 中的资源限制：

If server resources are limited, you can reduce the resource limits in docker-compose.yml:

```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'      # 降低 CPU 限制
      memory: 1G       # 降低内存限制
    reservations:
      cpus: '0.25'
      memory: 256M
  shm_size: 1gb       # 降低共享内存
```

## 故障排除 (Troubleshooting)

### 问题 1: 容器启动失败 (Container Startup Failure)

**症状**: 容器启动时出现错误
**症状**: Errors during container startup

**解决方案**:
**Solution**:
```bash
# 查看详细日志
docker-compose logs backend

# 重新构建镜像
docker-compose build --no-cache backend

# 检查磁盘空间
df -h
```

### 问题 2: 浏览器下载失败 (Browser Download Failure)

**症状**: 日志显示 Playwright 错误
**症状**: Logs show Playwright errors

**解决方案**:
**Solution**:
```bash
# 检查浏览器是否安装
docker-compose exec backend playwright install --help

# 重新安装浏览器
docker-compose exec backend playwright install chromium
docker-compose exec backend playwright install-deps chromium
```

### 问题 3: 内存不足 (Out of Memory)

**症状**: 容器被 OOM Killer 杀死
**症状**: Container killed by OOM Killer

**解决方案**:
**Solution**:
```yaml
# 增加 docker-compose.yml 中的内存限制
deploy:
  resources:
    limits:
      memory: 4G  # 增加到 4GB
  shm_size: 4gb   # 增加共享内存
```

### 问题 4: 共享内存不足 (Insufficient Shared Memory)

**症状**: Chromium 崩溃，日志显示 "DevToolsActivePort file doesn't exist"
**症状**: Chromium crashes, logs show "DevToolsActivePort file doesn't exist"

**解决方案**:
**Solution**:
```yaml
# 增加 docker-compose.yml 中的 shm_size
shm_size: 2gb  # 或更大，如 4gb
```

## 监控和日志 (Monitoring and Logging)

### 关键日志指标 (Key Log Metrics)

1. **下载方法分布** (Download method distribution):
   - `aiohttp`: 常规 HTTP 下载
   - `browser`: 浏览器回退下载

2. **回退触发原因** (Fallback trigger reasons):
   - HTTP 403/429/503
   - 连接超时
   - SSL 错误

3. **性能指标** (Performance metrics):
   - 下载时间
   - 文件大小
   - 下载成功率

### 日志示例 (Log Examples)

```
# 成功的回退下载
🔄 [FALLBACK] Attempting aiohttp download for: https://example.com/audio.mp3...
⚠️ [FALLBACK] aiohttp download failed: HTTPException
🌐 [FALLBACK] Triggering browser fallback download...
🌐 [BROWSER DOWNLOAD] Starting browser download for: https://example.com/audio.mp3...
✅ [BROWSER DOWNLOAD] Successfully downloaded to /app/temp/audio.mp3, size: 52428800 bytes
✅ [FALLBACK] Browser fallback download succeeded
```

## 安全考虑 (Security Considerations)

1. **沙盒模式**: Chromium 在 Docker 容器中以 `--no-sandbox` 模式运行（容器已提供隔离）

   **Sandbox mode**: Chromium runs with `--no-sandbox` in Docker container (container already provides isolation)

2. **用户代理**: 使用真实浏览器 User-Agent 以避免被检测

   **User agent**: Uses real browser User-Agent to avoid detection

3. **资源限制**: Docker 资源限制防止浏览器占用过多资源

   **Resource limits**: Docker resource limits prevent browser from consuming excessive resources

## 未来改进 (Future Improvements)

- [ ] 支持更多浏览器类型 (Firefox, WebKit)
- [ ] 添加浏览器缓存机制
- [ ] 实现下载重试策略优化
- [ ] 添加更详细的性能监控指标
- [ ] 支持浏览器插件扩展

- [ ] Support more browser types (Firefox, WebKit)
- [ ] Add browser caching mechanism
- [ ] Implement optimized download retry strategy
- [ ] Add more detailed performance monitoring metrics
- [ ] Support browser plugin extensions

## 相关文档 (Related Documentation)

- [Playwright 官方文档](https://playwright.dev/python/)
- [Chromium Docker 指南](https://github.com/GoogleChrome/chrome-launcher/blob/main/docs/chrome-flags-for-tools.md)
- [播客转录功能文档](../backend/app/domains/podcast/README.md)

## 维护者 (Maintainers)

- DevOps Team
- Backend Development Team

---

**最后更新** (Last Updated): 2026-01-03
