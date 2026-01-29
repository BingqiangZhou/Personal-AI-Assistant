# Podcast Audio Download Fallback Mechanism
# 播客音频下载回退机制

## Document Information / 文档信息

| Field / 字段 | Value / 值 |
|-------------|-----------|
| **Document ID / 文档ID** | PRD-2026-001 |
| **Created / 创建时间** | 2026-01-03 |
| **Status / 状态** | ✅ **COMPLETED (WITH CONDITIONS)** / **已完成（有条件）** |
| **Priority / 优先级** | Medium / 中等 |
| **Author / 作者** | Product Manager |
| **Assignees / 执行人** | Backend Developer, Test Engineer |
| **Verification Date / 验收日期** | 2026-01-03 |
| **Verification Report / 验收报告** | `specs/verification/podcast-audio-download-fallback-verification-2026-01-03.md` |

---

## Executive Summary / 概述

### Problem Statement / 问题陈述

**English:**
Currently, the podcast transcription service uses `aiohttp` to download audio files. However, some podcast audio URLs are protected by anti-scraping measures (e.g., Cloudflare, Akamai CDN protections) that block direct HTTP requests from non-browser clients. When `aiohttp` downloads fail, the transcription task cannot proceed, resulting in a poor user experience.

**中文:**
当前播客转录服务使用 `aiohttp` 下载音频文件。然而，部分播客音频 URL 受到反爬虫保护（如 Cloudflare、Akamai CDN 防护），会阻止来自非浏览器客户端的直接 HTTP 请求。当 `aiohttp` 下载失败时，转录任务无法继续执行，导致用户体验不佳。

### Proposed Solution / 解决方案

**English:**
Implement a browser-based fallback mechanism that automatically launches a headless browser (Playwright/Selenium) to download the audio file when `aiohttp` fails. This ensures higher download success rates for protected audio sources.

**中文:**
实现基于浏览器的回退机制，当 `aiohttp` 失败时自动启动无头浏览器（Playwright/Selenium）下载音频文件。确保受保护的音频源有更高的下载成功率。

### Success Metrics / 成功指标

**English:**
- Increase audio download success rate from current ~85% to >95%
- Reduce transcription task failures due to download errors by 70%
- Maintain average download time < 30 seconds for files < 50MB
- Browser fallback should trigger within 5 seconds of aiohttp failure

**中文:**
- 将音频下载成功率从当前的 ~85% 提升至 >95%
- 因下载错误导致的转录任务失败率降低 70%
- 50MB 以下文件的平均下载时间保持在 30 秒以内
- 浏览器回退应在 aiohttp 失败后 5 秒内触发

---

## User Analysis / 用户分析

### Target Personas / 目标用户

1. **Podcast Subscriber / 播客订阅者**
   - **Needs / 需求**: Subscribe to various podcast sources, including those with CDN protection
   - **Pain Points / 痛点**: Transcription fails for certain episodes without clear reason
   - **Language / 语言**: Bilingual (Chinese/English)

2. **Content Creator / 内容创作者**
   - **Needs / 需求**: Transcribe podcast episodes for content repurposing
   - **Pain Points / 痛点**: Unreliable transcription affects workflow
   - **Language / 语言**: Bilingual (Chinese/English)

### User Stories / 用户故事

#### US-001: Automatic Fallback for Failed Downloads
**English:**
> **As a** podcast subscriber
> **I want** the system to automatically try alternative download methods when the initial download fails
> **So that** my transcription tasks succeed even for protected audio sources

**中文:**
> **作为**播客订阅者
> **我想要**系统在初始下载失败时自动尝试备用下载方法
> **以便**即使对于受保护的音频源，我的转录任务也能成功

**Acceptance Criteria / 验收标准:**
- [ ] When aiohttp download fails with HTTP error (403, 429, 503), automatically trigger browser download
- [ ] User receives notification about fallback method being used
- [ ] Transcription task proceeds normally after successful fallback download
- [ ] Both success and failure scenarios are logged appropriately

#### US-002: Transparent Fallback Logging
**English:**
> **As a** system administrator
> **I want** to see clear logs indicating which download method was used
> **So that** I can monitor and troubleshoot download issues

**中文:**
> **作为**系统管理员
> **我想要**看到清晰的日志显示使用了哪种下载方法
> **以便**我可以监控和排查下载问题

**Acceptance Criteria / 验收标准:**
- [ ] Logs clearly indicate "aiohttp download" vs "browser fallback download"
- [ ] Download method is recorded in transcription task metadata
- [ ] API response includes download method information
- [ ] Error logs include detailed diagnostic information for both methods

---

## Functional Requirements / 功能需求

### FR-001: Dual Download Strategy
**English:**
The system must implement a two-tier download strategy:
1. **Primary Method**: Use existing `aiohttp` with browser User-Agent
2. **Fallback Method**: Launch headless browser when primary fails

**中文:**
系统必须实现两层下载策略：
1. **主方法**：使用现有的带浏览器 User-Agent 的 `aiohttp`
2. **回退方法**：主方法失败时启动无头浏览器

**Technical Specs / 技术规范:**
```python
class AudioDownloader:
    async def download_file_with_fallback(
        self,
        url: str,
        destination: str,
        progress_callback=None
    ) -> Tuple[str, int, str]:  # (path, size, method_used)
        """
        Download with automatic fallback to browser

        Args:
            url: Audio URL
            destination: Save path
            progress_callback: Progress callback

        Returns:
            Tuple[file_path, file_size, download_method]

        Raises:
            HTTPException: If both methods fail
        """
        # 1. Try aiohttp first
        try:
            return await self._download_with_aiohttp(url, destination, progress_callback) + ("aiohttp",)
        except HTTPException as e:
            logger.warning(f"aiohttp download failed: {e}, trying browser fallback")
            # 2. Fallback to browser
            return await self._download_with_browser(url, destination, progress_callback) + ("browser",)
```

### FR-002: Browser Download Implementation
**English:**
Use Playwright for headless browser automation:
- Launch Chromium in headless mode
- Navigate to audio URL directly
- Handle download completion event
- Support progress tracking
- Cleanup browser resources after download

**中文:**
使用 Playwright 进行无头浏览器自动化：
- 在无头模式下启动 Chromium
- 直接导航到音频 URL
- 处理下载完成事件
- 支持进度跟踪
- 下载后清理浏览器资源

**Technical Specs / 技术规范:**
```python
class BrowserAudioDownloader:
    async def download_with_playwright(
        self,
        url: str,
        destination: str,
        progress_callback=None,
        timeout: int = 300
    ) -> Tuple[str, int]:
        """
        Download audio using Playwright browser

        Args:
            url: Audio URL
            destination: Save path
            progress_callback: Progress callback
            timeout: Download timeout in seconds

        Returns:
            Tuple[file_path, file_size]

        Raises:
            HTTPException: If browser download fails
        """
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                accept_downloads=True,
                user_agent='Mozilla/5.0 ...'  # Standard browser UA
            )

            page = await context.new_page()

            # Setup download handler
            download_path = None

            async def handle_download(download):
                nonlocal download_path
                download_path = await download.path()
                # Move to destination
                shutil.move(download_path, destination)

            page.on('download', handle_download)

            # Navigate to URL (triggers download)
            await page.goto(url, wait_until='domcontentloaded', timeout=timeout*1000)

            # Wait for download to complete
            max_wait = timeout
            start_wait = time.time()
            while not download_path and (time.time() - start_wait) < max_wait:
                await asyncio.sleep(0.5)

            if not download_path:
                raise HTTPException(
                    status_code=408,
                    detail="Browser download timeout"
                )

            await browser.close()

            file_size = os.path.getsize(destination)
            return destination, file_size
```

### FR-003: Error Classification and Triggers
**English:**
Only trigger browser fallback for specific error types:
- HTTP 403 (Forbidden)
- HTTP 429 (Too Many Requests)
- HTTP 503 (Service Unavailable)
- Connection timeout errors
- SSL certificate errors

**中文:**
仅在特定错误类型时触发浏览器回退：
- HTTP 403（禁止访问）
- HTTP 429（请求过多）
- HTTP 503（服务不可用）
- 连接超时错误
- SSL 证书错误

**Technical Specs / 技术规范:**
```python
def should_trigger_fallback(error: Exception) -> bool:
    """
    Determine if browser fallback should be triggered

    Args:
        error: The exception from aiohttp download

    Returns:
        bool: True if fallback should be triggered
    """
    if isinstance(error, HTTPException):
        return error.status_code in [403, 429, 503]
    elif isinstance(error, (asyncio.TimeoutError, aiohttp.ClientError)):
        return True
    elif isinstance(error, ssl.SSLError):
        return True
    return False
```

### FR-004: Download Method Tracking
**English:**
Track which download method was used in the transcription task:
- Add `download_method` field to TranscriptionTask model
- Log download method in task progress updates
- Include download method in API responses

**中文:**
在转录任务中跟踪使用的下载方法：
- 在 TranscriptionTask 模型中添加 `download_method` 字段
- 在任务进度更新中记录下载方法
- 在 API 响应中包含下载方法

**Database Schema Change / 数据库架构变更:**
```sql
ALTER TABLE transcription_tasks
ADD COLUMN download_method VARCHAR(20) DEFAULT 'aiohttp'
CHECK (download_method IN ('aiohttp', 'browser', 'none'));

-- Add index for analytics
CREATE INDEX idx_transcription_tasks_download_method
ON transcription_tasks(download_method);
```

---

## Non-Functional Requirements / 非功能性需求

### NFR-001: Performance
**English:**
- Browser fallback should add no more than 10 seconds overhead compared to direct aiohttp success
- Browser initialization should complete within 3 seconds
- Memory usage per browser instance should not exceed 500MB

**中文:**
- 与 aiohttp 成功下载相比，浏览器回退不应增加超过 10 秒的开销
- 浏览器初始化应在 3 秒内完成
- 每个浏览器实例的内存使用不应超过 500MB

### NFR-002: Reliability
**English:**
- Browser process cleanup must be guaranteed, even on errors
- Timeout mechanisms must prevent browser hangs
- Concurrent downloads must use isolated browser contexts

**中文:**
- 必须保证浏览器进程清理，即使在出错情况下
- 超时机制必须防止浏览器挂起
- 并发下载必须使用隔离的浏览器上下文

### NFR-003: Resource Management
**English:**
- Maximum 3 concurrent browser instances
- Browser downloads should time out after 5 minutes
- Temporary download files must be cleaned up

**中文:**
- 最多 3 个并发浏览器实例
- 浏览器下载应在 5 分钟后超时
- 必须清理临时下载文件

### NFR-004: Observability
**English:**
- All download attempts must be logged with method used
- Success/failure rates must be tracked per method
- Performance metrics (time, size, speed) must be recorded

**中文:**
- 所有下载尝试必须记录使用的方法
- 必须跟踪每种方法的成功率/失败率
- 必须记录性能指标（时间、大小、速度）

---

## Technical Considerations / 技术考虑

### Dependencies / 依赖项

**Python Packages Required:**
```txt
playwright==1.40.0
```

**System Dependencies:**
```bash
# Install Playwright browsers
playwright install chromium
```

### Architecture Changes / 架构变更

**English:**
1. Create new `BrowserAudioDownloader` class in `transcription.py`
2. Modify `AudioDownloader` to support fallback strategy
3. Update `execute_transcription_task()` to use fallback method
4. Add browser download metrics to task metadata

**中文:**
1. 在 `transcription.py` 中创建新的 `BrowserAudioDownloader` 类
2. 修改 `AudioDownloader` 以支持回退策略
3. 更新 `execute_transcription_task()` 以使用回退方法
4. 将浏览器下载指标添加到任务元数据

### Error Handling / 错误处理

**English:**
- Catch and log browser launch failures separately
- Implement retry logic (max 1 retry for browser method)
- Provide clear error messages indicating which method failed
- Preserve original error details for debugging

**中文:**
- 单独捕获并记录浏览器启动失败
- 实现重试逻辑（浏览器方法最多重试 1 次）
- 提供清晰的错误消息指示哪种方法失败
- 保留原始错误详细信息用于调试

### Security Considerations / 安全考虑

**English:**
- Browser runs in headless mode (no GUI)
- Downloads restricted to audio file types
- Temporary files isolated in dedicated directory
- Browser context destroyed after download

**中文:**
- 浏览器在无头模式下运行（无 GUI）
- 下载限制为音频文件类型
- 临时文件隔离在专用目录中
- 下载后销毁浏览器上下文

---

## Implementation Plan / 实施计划

### Phase 1: Core Browser Download (Week 1)
**English:**
- Implement `BrowserAudioDownloader` class with Playwright
- Add basic download functionality
- Write unit tests for browser download

**中文:**
- 使用 Playwright 实现 `BrowserAudioDownloader` 类
- 添加基本下载功能
- 为浏览器下载编写单元测试

### Phase 2: Fallback Integration (Week 1-2)
**English:**
- Modify `AudioDownloader` to support fallback
- Implement error classification logic
- Integrate browser download into transcription workflow
- Add download method tracking to database

**中文:**
- 修改 `AudioDownloader` 以支持回退
- 实现错误分类逻辑
- 将浏览器下载集成到转录工作流中
- 将下载方法跟踪添加到数据库

### Phase 3: Testing & Monitoring (Week 2)
**English:**
- Write comprehensive integration tests
- Add logging and metrics
- Test with real protected audio sources
- Performance benchmarking

**中文:**
- 编写全面的集成测试
- 添加日志和指标
- 使用真实的受保护音频源进行测试
- 性能基准测试

### Phase 4: Deployment & Validation (Week 3)
**English:**
- Deploy to staging environment
- Monitor download success rates
- Collect performance metrics
- Address any issues
- Deploy to production

**中文:**
- 部署到测试环境
- 监控下载成功率
- 收集性能指标
- 解决任何问题
- 部署到生产环境

---

## Testing Strategy / 测试策略

### Unit Tests / 单元测试

**File**: `backend/app/domains/podcast/tests/test_audio_download_fallback.py`

```python
import pytest
from app.domains.podcast.transcription import (
    AudioDownloader,
    BrowserAudioDownloader,
    should_trigger_fallback
)
from fastapi import HTTPException

class TestAudioDownloadFallback:
    """Test audio download fallback mechanism / 测试音频下载回退机制"""

    @pytest.mark.asyncio
    async def test_aiohttp_success_no_fallback(self):
        """Test that fallback is not triggered when aiohttp succeeds / 测试 aiohttp 成功时不触发回退"""
        # Implementation
        pass

    @pytest.mark.asyncio
    async def test_403_error_triggers_browser_fallback(self):
        """Test that 403 error triggers browser fallback / 测试 403 错误触发浏览器回退"""
        # Implementation
        pass

    @pytest.mark.asyncio
    async def test_429_error_triggers_browser_fallback(self):
        """Test that 429 error triggers browser fallback / 测试 429 错误触发浏览器回退"""
        # Implementation
        pass

    @pytest.mark.asyncio
    async def test_browser_download_success(self, mock_playwright):
        """Test successful browser download / 测试浏览器下载成功"""
        # Implementation
        pass

    @pytest.mark.asyncio
    async def test_both_methods_fail_raises_error(self):
        """Test that error is raised when both methods fail / 测试两种方法都失败时抛出错误"""
        # Implementation
        pass

    @pytest.mark.asyncio
    async def test_download_method_tracked_in_db(self, db_session):
        """Test that download method is tracked in database / 测试下载方法在数据库中跟踪"""
        # Implementation
        pass

    def test_should_trigger_fallback_403(self):
        """Test error classification for 403 / 测试 403 错误分类"""
        error = HTTPException(status_code=403, detail="Forbidden")
        assert should_trigger_fallback(error) is True

    def test_should_trigger_fallback_500_no_trigger(self):
        """Test that 500 error does not trigger fallback / 测试 500 错误不触发回退"""
        error = HTTPException(status_code=500, detail="Internal Server Error")
        assert should_trigger_fallback(error) is False
```

### Integration Tests / 集成测试

**Test Scenarios:**
1. **End-to-end transcription with browser fallback**
   - Subscribe to podcast with protected audio
   - Trigger transcription
   - Verify browser download is used
   - Verify transcription completes

2. **Concurrent downloads with mixed methods**
   - Multiple episodes: some aiohttp, some browser
   - Verify no resource conflicts
   - Verify all complete successfully

3. **Browser resource cleanup on error**
   - Simulate browser crash during download
   - Verify processes are cleaned up
   - Verify no orphaned browser instances

### Performance Tests / 性能测试

```python
@pytest.mark.performance
@pytest.mark.asyncio
async def test_browser_overhead_acceptable(self):
    """Test that browser fallback adds acceptable overhead / 测试浏览器回返开销可接受"""
    # Measure browser download time vs aiohttp
    # Overhead should be < 10 seconds
    pass

@pytest.mark.performance
@pytest.mark.asyncio
async def test_concurrent_browser_downloads(self):
    """Test concurrent browser downloads stay within limits / 测试并发浏览器下载保持在限制内"""
    # Launch 3 simultaneous browser downloads
    # Verify memory usage < 500MB per instance
    pass
```

---

## Success Metrics Dashboard / 成功指标仪表板

### Key Performance Indicators (KPIs)

| Metric / 指标 | Current / 当前 | Target / 目标 | Measurement / 测量方法 |
|--------------|---------------|--------------|---------------------|
| Download Success Rate / 下载成功率 | 85% | >95% | (successful downloads / total downloads) × 100 |
| Browser Fallback Rate / 浏览器回退率 | N/A | 10-15% | (browser downloads / total downloads) × 100 |
| Avg Download Time (aiohttp) / 平均下载时间 | 20s | <25s | Average time for successful aiohttp downloads |
| Avg Download Time (browser) / 平均下载时间（浏览器） | N/A | <35s | Average time for browser downloads |
| Transcription Failure Rate (download errors) / 转录失败率 | 12% | <4% | (failed transcriptions / total transcriptions) × 100 |
| Browser Instance Memory Usage / 浏览器内存使用 | N/A | <500MB | Peak memory per browser instance |

### Monitoring & Alerts / 监控与告警

**English:**
- Set up alert if browser fallback rate exceeds 20%
- Monitor browser crash rate
- Track average download time per method
- Alert on memory usage per browser instance

**中文:**
- 如果浏览器回退率超过 20%，设置告警
- 监控浏览器崩溃率
- 跟踪每种方法的平均下载时间
- 在每个浏览器实例的内存使用上设置告警

---

## Risks & Mitigations / 风险与缓解

| Risk / 风险 | Impact / 影响 | Probability / 概率 | Mitigation / 缓解措施 |
|------------|-------------|-------------------|-------------------|
| Browser download slower than expected / 浏览器下载比预期慢 | High / 高 | Medium / 中 | Set strict timeouts, provide progress updates, allow user cancellation |
| Browser resource leaks / 浏览器资源泄漏 | High / 高 | Low / 低 | Implement guaranteed cleanup in finally blocks, monitor memory |
| Playwright installation issues in Docker / Docker 中 Playwright 安装问题 | Medium / 中 | Medium / 中 | Document installation steps, provide Dockerfile updates |
| Some sites still block browser downloads / 某些网站仍然阻止浏览器下载 | Medium / 中 | Low / 低 | Log these cases for analysis, consider additional strategies |
| Concurrent browser downloads exceed memory limits / 并发浏览器下载超过内存限制 | Medium / 中 | Low / 低 | Implement semaphore to limit concurrent browsers |

---

## Dependencies & Blockers / 依赖和阻碍

### Technical Dependencies / 技术依赖

- [ ] Playwright Python package installed
- [ ] Chromium browser installed via `playwright install`
- [ ] Database migration for `download_method` field
- [ ] AsyncIO event loop supports subprocess execution

### External Dependencies / 外部依赖

- [ ] Access to test podcast feeds with protected audio
- [ ] Sufficient server memory for browser instances (recommend 2GB+ available)

---

## Open Questions / 待解决问题

1. **Browser Timeout Configuration / 浏览器超时配置**
   - Q: Should different timeout values be used for different file sizes?
   - 问：是否应该为不同的文件大小使用不同的超时值？
   - A: Start with 5-minute fixed timeout, adjust based on metrics

2. **Browser Type Selection / 浏览器类型选择**
   - Q: Should we support Firefox/WebKit as fallback browsers?
   - 问：我们应该支持 Firefox/WebKit 作为回退浏览器吗？
   - A: Chromium only for MVP, evaluate others if needed

3. **User Preference / 用户偏好**
   - Q: Should users be able to disable browser fallback for privacy?
   - 问：用户是否应该能够出于隐私原因禁用浏览器回退？
   - A: Not for MVP, consider in future iterations

---

## Glossary / 词汇表

| Term / 术语 | Definition / 定义 |
|-----------|-----------------|
| **aiohttp** / **aiohttp** | Async HTTP client library used for primary downloads / 用于主下载的异步 HTTP 客户端库 |
| **Playwright** / **Playwright** | Browser automation library for Python / Python 浏览器自动化库 |
| **Headless Browser** / **无头浏览器** | Browser running without GUI (no visible window) / 无 GUI 运行的浏览器（无可视窗口） |
| **CDN Protection** / **CDN 防护** | Anti-bot measures from content delivery networks / 内容分发网络的反机器人措施 |
| **Fallback Mechanism** / **回退机制** | Alternative method used when primary method fails / 主方法失败时使用的替代方法 |
| **User-Agent** / **User-Agent** | HTTP header identifying the client type / 标识客户端类型的 HTTP 头 |

---

## Changelog / 变更日志

| Date / 日期 | Version / 版本 | Changes / 变更 | Author / 作者 |
|------------|---------------|---------------|--------------|
| 2026-01-03 | 0.1 | Initial document creation / 初始文档创建 | Product Manager |

---

## Appendix / 附录

### A. Related Documents / 相关文档

- [Podcast Transcription Architecture](./podcast-transcription-architecture.md)
- [Error Handling Guidelines](../engineering/error-handling-guidelines.md)
- [Performance Testing Standards](../engineering/performance-testing-standards.md)

### B. Reference Implementations / 参考实现

- Playwright Python Documentation: https://playwright.dev/python/
- aiohttp Documentation: https://docs.aiohttp.org/
- AsyncIO Subprocess Management: https://docs.python.org/3/library/asyncio-subprocess.html

### C. Example Error Messages / 示例错误消息

**English:**
```json
{
  "detail": "Audio download failed using both HTTP and browser methods",
  "type": "AudioDownloadError",
  "errors": [
    {
      "method": "aiohttp",
      "error": "HTTP 403: Forbidden",
      "timestamp": "2026-01-03T10:30:00Z"
    },
    {
      "method": "browser",
      "error": "Browser download timeout after 300s",
      "timestamp": "2026-01-03T10:35:00Z"
    }
  ]
}
```

**中文:**
```json
{
  "detail": "音频下载失败（已尝试 HTTP 和浏览器两种方法）",
  "type": "AudioDownloadError",
  "errors": [
    {
      "method": "aiohttp",
      "error": "HTTP 403: 禁止访问",
      "timestamp": "2026-01-03T10:30:00Z"
    },
    {
      "method": "browser",
      "error": "浏览器下载超时（300秒后）",
      "timestamp": "2026-01-03T10:35:00Z"
    }
  ]
}
```
