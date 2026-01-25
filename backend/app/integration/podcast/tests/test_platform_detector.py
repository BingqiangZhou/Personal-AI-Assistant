"""
Unit tests for podcast platform detection
"""

from app.integration.podcast.platform_detector import (
    PlatformDetector,
    PodcastPlatform,
)


class TestPlatformDetector:
    """Test platform detection logic"""

    def test_detect_xiaoyuzhou_platform(self):
        """Test detection of Xiaoyuzhou RSS feeds"""
        urls = [
            "https://feed.xyzfm.space/mcklbwxjdvfu",
            "https://xiaoyuzhou.fm/podcast/123",
            "https://www.xiaoyuzhoufm.com/episodes/456",
        ]

        for url in urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform == PodcastPlatform.XIAOYUZHOU, f"Failed for URL: {url}"

    def test_detect_ximalaya_platform(self):
        """Test detection of Ximalaya RSS feeds"""
        urls = [
            "https://www.ximalaya.com/album/51076156.xml",
            "https://ximalaya.com/album/12345.xml",
            "https://www.xmcdn.com/feed/123.xml",
        ]

        for url in urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform == PodcastPlatform.XIMALAYA, f"Failed for URL: {url}"

    def test_detect_generic_platform(self):
        """Test detection of generic RSS feeds"""
        urls = [
            "https://example.com/podcast.rss",
            "https://feeds.megaphone.fm/podcast",
            "https://anchor.fm/s/12345/podcast/rss",
        ]

        for url in urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform == PodcastPlatform.GENERIC, f"Failed for URL: {url}"

    def test_validate_ximalaya_url_valid(self):
        """Test validation of valid Ximalaya URLs"""
        valid_urls = [
            "https://www.ximalaya.com/album/51076156.xml",
            "https://ximalaya.com/album/12345.xml",
            "http://www.ximalaya.com/album/999.xml",
            "https://www.ximalaya.com/rss/album/123",
        ]

        for url in valid_urls:
            is_valid, error = PlatformDetector.validate_platform_url(
                url, PodcastPlatform.XIMALAYA
            )
            assert is_valid, f"Should be valid: {url}, error: {error}"
            assert error is None

    def test_validate_ximalaya_url_invalid(self):
        """Test validation of invalid Ximalaya URLs"""
        invalid_urls = [
            "https://www.ximalaya.com/album/",
            "https://www.ximalaya.com/podcast/123",
            "https://example.com/feed.xml",
            "https://www.ximalaya.com/",
        ]

        for url in invalid_urls:
            is_valid, error = PlatformDetector.validate_platform_url(
                url, PodcastPlatform.XIMALAYA
            )
            assert not is_valid, f"Should be invalid: {url}"
            assert error is not None
            assert "Invalid Ximalaya RSS URL format" in error

    def test_validate_xiaoyuzhou_url_valid(self):
        """Test validation of valid Xiaoyuzhou URLs"""
        valid_urls = [
            "https://feed.xyzfm.space/mcklbwxjdvfu",
            "https://xiaoyuzhou.fm/podcast.xml",
            "https://www.xiaoyuzhoufm.com/rss/123",
        ]

        for url in valid_urls:
            is_valid, error = PlatformDetector.validate_platform_url(
                url, PodcastPlatform.XIAOYUZHOU
            )
            assert is_valid, f"Should be valid: {url}, error: {error}"
            assert error is None

    def test_validate_xiaoyuzhou_url_invalid(self):
        """Test validation of invalid Xiaoyuzhou URLs"""
        invalid_urls = [
            "https://example.com/feed.xml",
            "https://www.ximalaya.com/album/123.xml",
        ]

        for url in invalid_urls:
            is_valid, error = PlatformDetector.validate_platform_url(
                url, PodcastPlatform.XIAOYUZHOU
            )
            assert not is_valid, f"Should be invalid: {url}"
            assert error is not None

    def test_validate_generic_platform_always_valid(self):
        """Test that generic platform accepts any URL"""
        urls = [
            "https://example.com/feed.xml",
            "https://any-domain.com/rss",
        ]

        for url in urls:
            is_valid, error = PlatformDetector.validate_platform_url(
                url, PodcastPlatform.GENERIC
            )
            assert is_valid
            assert error is None

    def test_detect_platform_case_insensitive(self):
        """Test platform detection is case insensitive"""
        urls = [
            ("https://WWW.XIMALAYA.COM/album/123.xml", PodcastPlatform.XIMALAYA),
            ("https://XIAOYUZHOU.FM/feed.xml", PodcastPlatform.XIAOYUZHOU),
        ]

        for url, expected_platform in urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform == expected_platform

    def test_detect_platform_with_invalid_url(self):
        """Test platform detection with malformed URLs"""
        invalid_urls = [
            "not-a-url",
            "",
            "ftp://invalid.com",
        ]

        for url in invalid_urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform == PodcastPlatform.GENERIC
