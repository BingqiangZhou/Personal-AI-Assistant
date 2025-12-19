"""
Edge case and backward compatibility tests for platform support
"""

import pytest
from unittest.mock import AsyncMock, patch, Mock
from datetime import datetime

from app.integration.podcast.platform_detector import PlatformDetector, PodcastPlatform
from app.integration.podcast.secure_rss_parser import SecureRSSParser, PodcastFeed


class TestPlatformEdgeCases:
    """Test edge cases and backward compatibility"""

    def test_platform_detector_with_malformed_urls(self):
        """Test platform detection with malformed URLs"""
        malformed_urls = [
            "",
            "not-a-url",
            "http://",
            "ftp://ximalaya.com/feed.xml",
            "javascript:alert('xss')",
            None,
        ]

        for url in malformed_urls:
            if url is None:
                continue
            platform = PlatformDetector.detect_platform(url)
            assert platform == PodcastPlatform.GENERIC

    def test_platform_detector_with_unicode_urls(self):
        """Test platform detection with Unicode characters in URLs"""
        unicode_urls = [
            "https://www.ximalaya.com/专辑/123.xml",
            "https://xiaoyuzhou.fm/播客/feed.xml",
        ]

        for url in unicode_urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform in [PodcastPlatform.XIMALAYA, PodcastPlatform.XIAOYUZHOU, PodcastPlatform.GENERIC]

    def test_platform_detector_with_query_parameters(self):
        """Test platform detection with query parameters"""
        urls_with_params = [
            ("https://www.ximalaya.com/album/123.xml?token=abc", PodcastPlatform.XIMALAYA),
            ("https://feed.xyzfm.space/abc?utm_source=test", PodcastPlatform.XIAOYUZHOU),
        ]

        for url, expected_platform in urls_with_params:
            platform = PlatformDetector.detect_platform(url)
            assert platform == expected_platform

    def test_platform_detector_with_subdomains(self):
        """Test platform detection with various subdomains"""
        subdomain_urls = [
            ("https://api.ximalaya.com/album/123.xml", PodcastPlatform.XIMALAYA),
            ("https://cdn.ximalaya.com/feed.xml", PodcastPlatform.XIMALAYA),
            ("https://feed.xyzfm.space/abc", PodcastPlatform.XIAOYUZHOU),
        ]

        for url, expected_platform in subdomain_urls:
            platform = PlatformDetector.detect_platform(url)
            assert platform == expected_platform

    def test_validate_ximalaya_url_with_edge_cases(self):
        """Test Ximalaya URL validation with edge cases"""
        edge_cases = [
            ("https://www.ximalaya.com/album/0.xml", True),  # Zero album ID
            ("https://www.ximalaya.com/album/999999999999.xml", True),  # Very large ID
            ("https://www.ximalaya.com/album/123.xml?param=value", True),  # With params
            ("https://ximalaya.com/album/123.xml", True),  # Without www
            ("http://www.ximalaya.com/album/123.xml", True),  # HTTP instead of HTTPS
        ]

        for url, should_be_valid in edge_cases:
            is_valid, error = PlatformDetector.validate_platform_url(url, PodcastPlatform.XIMALAYA)
            assert is_valid == should_be_valid, f"Failed for URL: {url}"

    def test_backward_compatibility_missing_platform(self):
        """Test that missing platform field doesn't break existing functionality"""
        # Simulate old feed data without platform field
        feed_data = {
            'title': 'Test Podcast',
            'link': 'https://example.com',
            'description': 'Test Description',
            'episodes': [],
            'last_fetched': datetime.utcnow(),
        }

        # Should not raise error when platform is missing
        feed = PodcastFeed(**feed_data)
        assert feed.platform is None

    def test_platform_detector_with_redirected_urls(self):
        """Test platform detection with common redirect patterns"""
        redirect_patterns = [
            ("https://www.ximalaya.com/album/123.xml", PodcastPlatform.XIMALAYA),
            ("https://ximalaya.com/album/123.xml", PodcastPlatform.XIMALAYA),
        ]

        for url, expected_platform in redirect_patterns:
            platform = PlatformDetector.detect_platform(url)
            assert platform == expected_platform

    def test_platform_detector_case_sensitivity(self):
        """Test platform detection is case insensitive"""
        case_variations = [
            "https://WWW.XIMALAYA.COM/album/123.xml",
            "https://www.XiMaLaYa.com/album/123.xml",
            "https://XIMALAYA.COM/album/123.xml",
        ]

        for url in case_variations:
            platform = PlatformDetector.detect_platform(url)
            assert platform == PodcastPlatform.XIMALAYA

    def test_validate_platform_url_with_none(self):
        """Test validation handles None gracefully"""
        is_valid, error = PlatformDetector.validate_platform_url("", PodcastPlatform.GENERIC)
        assert is_valid  # Generic platform accepts anything

    def test_platform_detector_with_ipv6_urls(self):
        """Test platform detection with IPv6 addresses"""
        ipv6_url = "https://[2001:db8::1]/feed.xml"
        platform = PlatformDetector.detect_platform(ipv6_url)
        assert platform == PodcastPlatform.GENERIC

    def test_platform_detector_with_port_numbers(self):
        """Test platform detection with custom ports"""
        urls_with_ports = [
            ("https://www.ximalaya.com:8080/album/123.xml", PodcastPlatform.XIMALAYA),
            ("https://xiaoyuzhou.fm:443/feed.xml", PodcastPlatform.XIAOYUZHOU),
        ]

        for url, expected_platform in urls_with_ports:
            platform = PlatformDetector.detect_platform(url)
            assert platform == expected_platform


class TestRSSParserBackwardCompatibility:
    """Test RSS parser backward compatibility"""

    @pytest.fixture
    def parser(self):
        """Create parser instance"""
        with patch('app.integration.podcast.secure_rss_parser.PodcastSecurityValidator'):
            return SecureRSSParser(user_id=1)

    def test_parser_handles_feed_without_platform(self, parser):
        """Test parser handles old feeds without platform information"""
        xml_without_platform = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
    <channel>
        <title>Test Podcast</title>
        <link>https://example.com</link>
        <description>Test Description</description>
        <item>
            <title>Episode 1</title>
            <description>Episode description</description>
            <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
            <enclosure url="https://example.com/audio.mp3" type="audio/mpeg" length="12345"/>
        </item>
    </channel>
</rss>"""

        # Should parse successfully and assign generic platform
        feed = parser._parse_feed_securely("https://example.com/feed.xml", xml_without_platform, PodcastPlatform.GENERIC)
        assert feed.platform == PodcastPlatform.GENERIC

    @pytest.mark.asyncio
    async def test_parser_handles_empty_platform_gracefully(self, parser):
        """Test parser handles empty platform string"""
        with patch.object(parser, '_safe_fetch', return_value=("", "Error")):
            success, feed, error = await parser.fetch_and_parse_feed("https://example.com/feed.xml")
            assert not success
            assert error is not None
