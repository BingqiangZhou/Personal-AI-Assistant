"""
播客音频下载回退机制测试 / Tests for Podcast Audio Download Fallback Mechanism

测试内容：
1. should_trigger_fallback 函数的边界情况
2. BrowserAudioDownloader 类的下载功能
3. AudioDownloader 的 download_file_with_fallback 方法
4. 集成测试：完整的下载流程
"""

import pytest
import asyncio
import os
import tempfile
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import HTTPException, status

from app.domains.podcast.transcription import (
    AudioDownloader,
    BrowserAudioDownloader,
    should_trigger_fallback
)


class TestShouldTriggerFallback:
    """测试 should_trigger_fallback 函数 / Test should_trigger_fallback function"""

    def test_trigger_on_403_error(self):
        """测试 403 错误触发回退 / Test 403 error triggers fallback"""
        error = HTTPException(status_code=403, detail="Forbidden")
        assert should_trigger_fallback(error) is True

    def test_trigger_on_429_error(self):
        """测试 429 错误触发回退 / Test 429 error triggers fallback"""
        error = HTTPException(status_code=429, detail="Too Many Requests")
        assert should_trigger_fallback(error) is True

    def test_trigger_on_503_error(self):
        """测试 503 错误触发回退 / Test 503 error triggers fallback"""
        error = HTTPException(status_code=503, detail="Service Unavailable")
        assert should_trigger_fallback(error) is True

    def test_trigger_on_408_timeout(self):
        """测试 408 超时错误触发回退 / Test 408 timeout triggers fallback"""
        error = HTTPException(status_code=408, detail="Request Timeout")
        assert should_trigger_fallback(error) is True

    def test_trigger_on_403_in_detail(self):
        """测试 detail 中包含 HTTP 403 触发回退 / Test HTTP 403 in detail triggers fallback"""
        error = HTTPException(status_code=500, detail="Failed to download audio file: HTTP 403")
        assert should_trigger_fallback(error) is True

    def test_no_trigger_on_500_error(self):
        """测试 500 错误不触发回退 / Test 500 error does not trigger fallback"""
        error = HTTPException(status_code=500, detail="Internal Server Error")
        assert should_trigger_fallback(error) is False

    def test_no_trigger_on_404_error(self):
        """测试 404 错误不触发回退 / Test 404 error does not trigger fallback"""
        error = HTTPException(status_code=404, detail="Not Found")
        assert should_trigger_fallback(error) is False

    def test_trigger_on_timeout_error(self):
        """测试 asyncio.TimeoutError 触发回退 / Test asyncio.TimeoutError triggers fallback"""
        error = asyncio.TimeoutError()
        assert should_trigger_fallback(error) is True

    def test_trigger_on_base_timeout(self):
        """测试 TimeoutError 触发回退 / Test TimeoutError triggers fallback"""
        error = TimeoutError()
        assert should_trigger_fallback(error) is True

    def test_trigger_on_generic_exception(self):
        """测试普通异常不触发回退 / Test generic exception does not trigger fallback"""
        error = ValueError("Some error")
        assert should_trigger_fallback(error) is False


class TestBrowserAudioDownloader:
    """测试 BrowserAudioDownloader 类 / Test BrowserAudioDownloader class"""

    @pytest.mark.asyncio
    async def test_browser_download_success(self):
        """测试浏览器下载成功 / Test successful browser download"""
        # 这个测试需要 Playwright 和真实的浏览器环境
        # 在 CI/CD 环境中可能需要跳过
        pytest.skip("Requires Playwright browser environment")

    @pytest.mark.asyncio
    async def test_browser_download_timeout(self):
        """测试浏览器下载超时 / Test browser download timeout"""
        pytest.skip("Requires Playwright browser environment")

    @pytest.mark.asyncio
    async def test_browser_concurrent_limit(self):
        """测试浏览器并发限制 / Test browser concurrent limit"""
        pytest.skip("Requires Playwright browser environment")


class TestAudioDownloaderFallback:
    """测试 AudioDownloader 的回退机制 / Test AudioDownloader fallback mechanism"""

    @pytest.mark.asyncio
    async def test_aiohttp_success_no_fallback(self):
        """测试 aiohttp 成功时不触发回退 / Test no fallback when aiohttp succeeds"""
        downloader = AudioDownloader()

        # Mock aiohttp session
        with patch.object(downloader, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {'content-length': '1000'}

            async def mock_iter_chunked(size):
                yield b'x' * 1000

            mock_response.content = Mock()
            mock_response.content.iter_chunked = mock_iter_chunked

            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.headers = {}

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name

            try:
                async with downloader:
                    file_path, file_size, method = await downloader.download_file_with_fallback(
                        "http://example.com/audio.mp3",
                        tmp_path
                    )

                assert method == "aiohttp"
                assert file_size == 1000
                assert os.path.exists(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_403_triggers_browser_fallback(self):
        """测试 403 错误触发浏览器回退 / Test 403 error triggers browser fallback"""
        downloader = AudioDownloader()

        # Mock aiohttp 失败，然后模拟浏览器下载成功
        with patch.object(downloader, 'session') as mock_session:
            # aiohttp 返回 403
            mock_response = AsyncMock()
            mock_response.status = 403
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.headers = {}

            # Mock BrowserAudioDownloader
            with patch('app.domains.podcast.transcription.BrowserAudioDownloader') as MockBrowserDownloader:
                mock_browser = AsyncMock()
                mock_browser.download_with_playwright = AsyncMock(return_value=("/path/to/file", 1000))

                MockBrowserDownloader.return_value = mock_browser

                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_path = tmp.name

                try:
                    async with downloader:
                        file_path, file_size, method = await downloader.download_file_with_fallback(
                            "http://example.com/audio.mp3",
                            tmp_path
                        )

                    assert method == "browser"
                    assert file_size == 1000
                    mock_browser.download_with_playwright.assert_called_once()
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_non_fallback_error_no_browser(self):
        """测试不可回退错误不触发浏览器 / Test non-fallback error doesn't trigger browser"""
        downloader = AudioDownloader()

        # Mock aiohttp 返回 500（不可回退）
        with patch.object(downloader, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 500
            mock_response.text = AsyncMock(return_value="Internal Server Error")
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.headers = {}

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name

            try:
                async with downloader:
                    with pytest.raises(HTTPException) as exc_info:
                        await downloader.download_file_with_fallback(
                            "http://example.com/audio.mp3",
                            tmp_path
                        )

                # 应该直接抛出异常，不尝试浏览器下载
                assert exc_info.value.status_code == 500
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

    @pytest.mark.asyncio
    async def test_both_methods_fail_raises_error(self):
        """测试两种方法都失败时抛出错误 / Test error when both methods fail"""
        downloader = AudioDownloader()

        # Mock aiohttp 失败（403）
        with patch.object(downloader, 'session') as mock_session:
            mock_response = AsyncMock()
            mock_response.status = 403
            mock_session.get = AsyncMock(return_value=mock_response)
            mock_session.headers = {}

            # Mock BrowserAudioDownloader 也失败
            with patch('app.domains.podcast.transcription.BrowserAudioDownloader') as MockBrowserDownloader:
                mock_browser = AsyncMock()
                mock_browser.download_with_playwright = AsyncMock(
                    side_effect=HTTPException(status_code=500, detail="Browser download failed")
                )

                MockBrowserDownloader.return_value = mock_browser

                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    tmp_path = tmp.name

                try:
                    async with downloader:
                        with pytest.raises(HTTPException) as exc_info:
                            await downloader.download_file_with_fallback(
                                "http://example.com/audio.mp3",
                                tmp_path
                            )

                    # 应该包含两种方法的错误信息
                    assert "both HTTP and browser methods" in exc_info.value.detail.lower()
                finally:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)


class TestIntegration:
    """集成测试 / Integration Tests"""

    @pytest.mark.asyncio
    async def test_end_to_end_fallback_flow(self):
        """测试端到端回退流程 / Test end-to-end fallback flow"""
        # 这个测试需要真实的环境，在 CI/CD 中可能需要跳过
        pytest.skip("Integration test - requires full environment")

    @pytest.mark.asyncio
    async def test_concurrent_downloads(self):
        """测试并发下载 / Test concurrent downloads"""
        pytest.skip("Integration test - requires full environment")


class TestEdgeCases:
    """边界情况测试 / Edge Case Tests"""

    @pytest.mark.asyncio
    async def test_empty_file_handling(self):
        """测试空文件处理 / Test empty file handling"""
        pytest.skip("Integration test - requires full environment")

    @pytest.mark.asyncio
    async def test_large_file_download(self):
        """测试大文件下载 / Test large file download"""
        pytest.skip("Integration test - requires full environment")

    @pytest.mark.asyncio
    async def test_network_interruption_recovery(self):
        """测试网络中断恢复 / Test network interruption recovery"""
        pytest.skip("Integration test - requires full environment")

    @pytest.mark.asyncio
    async def test_ssl_error_handling(self):
        """测试 SSL 错误处理 / Test SSL error handling"""
        # SSL 错误应该触发回退
        import ssl
        error = ssl.SSLError("SSL error")
        assert should_trigger_fallback(error) is True
