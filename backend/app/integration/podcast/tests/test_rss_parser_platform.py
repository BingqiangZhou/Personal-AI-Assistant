"""
Unit tests for RSS parser platform integration
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from app.integration.podcast.platform_detector import PodcastPlatform
from app.integration.podcast.secure_rss_parser import PodcastFeed, SecureRSSParser


class TestRSSParserPlatform:
    """Test RSS parser includes platform information"""

    @pytest.fixture
    def mock_security_validator(self):
        """Mock security validator"""
        with patch('app.integration.podcast.secure_rss_parser.PodcastSecurityValidator') as mock:
            validator = Mock()
            validator.validate_audio_url.return_value = (True, None)
            validator.MAX_RSS_SIZE = 10 * 1024 * 1024
            mock.return_value = validator
            yield validator

    @pytest.fixture
    def mock_content_validator(self):
        """Mock content validator"""
        with patch('app.integration.podcast.secure_rss_parser.PodcastContentValidator') as mock:
            validator = AsyncMock()
            validator.validate_rss_feed.return_value = {'valid': True, 'error': None}
            mock.return_value = validator
            yield validator

    @pytest.fixture
    def parser(self, mock_security_validator):
        """Create parser instance"""
        return SecureRSSParser(user_id=1)

    def create_mock_rss_xml(self, platform_url: str) -> str:
        """Create mock RSS XML content"""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:itunes="http://www.itunes.com/dtds/podcast-1.0.dtd">
    <channel>
        <title>Test Podcast</title>
        <link>{platform_url}</link>
        <description>Test Description</description>
        <item>
            <title>Episode 1</title>
            <description>Episode description</description>
            <pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate>
            <enclosure url="https://example.com/audio.mp3" type="audio/mpeg" length="12345"/>
            <guid>episode-1</guid>
        </item>
    </channel>
</rss>"""

    @pytest.mark.asyncio
    async def test_parser_detects_ximalaya_platform(self, parser, mock_content_validator):
        """Test parser detects Ximalaya platform from feed URL"""
        feed_url = "https://www.ximalaya.com/album/51076156.xml"
        xml_content = self.create_mock_rss_xml(feed_url)

        with patch.object(parser, '_safe_fetch', return_value=(xml_content, None)):
            success, feed, error = await parser.fetch_and_parse_feed(feed_url)

        assert success
        assert feed is not None
        assert feed.platform == PodcastPlatform.XIMALAYA
        assert error is None

    @pytest.mark.asyncio
    async def test_parser_detects_xiaoyuzhou_platform(self, parser, mock_content_validator):
        """Test parser detects Xiaoyuzhou platform from feed URL"""
        feed_url = "https://feed.xyzfm.space/mcklbwxjdvfu"
        xml_content = self.create_mock_rss_xml(feed_url)

        with patch.object(parser, '_safe_fetch', return_value=(xml_content, None)):
            success, feed, error = await parser.fetch_and_parse_feed(feed_url)

        assert success
        assert feed is not None
        assert feed.platform == PodcastPlatform.XIAOYUZHOU
        assert error is None

    @pytest.mark.asyncio
    async def test_parser_detects_generic_platform(self, parser, mock_content_validator):
        """Test parser detects generic platform for unknown feeds"""
        feed_url = "https://example.com/podcast.rss"
        xml_content = self.create_mock_rss_xml(feed_url)

        with patch.object(parser, '_safe_fetch', return_value=(xml_content, None)):
            success, feed, error = await parser.fetch_and_parse_feed(feed_url)

        assert success
        assert feed is not None
        assert feed.platform == PodcastPlatform.GENERIC
        assert error is None

    @pytest.mark.asyncio
    async def test_parser_includes_platform_in_feed_object(self, parser, mock_content_validator):
        """Test parser includes platform field in PodcastFeed object"""
        feed_url = "https://www.ximalaya.com/album/123.xml"
        xml_content = self.create_mock_rss_xml(feed_url)

        with patch.object(parser, '_safe_fetch', return_value=(xml_content, None)):
            success, feed, error = await parser.fetch_and_parse_feed(feed_url)

        assert success
        assert isinstance(feed, PodcastFeed)
        assert hasattr(feed, 'platform')
        assert feed.platform is not None

    @pytest.mark.asyncio
    async def test_parser_handles_multiple_platforms(self, parser, mock_content_validator):
        """Test parser correctly identifies different platforms"""
        test_cases = [
            ("https://www.ximalaya.com/album/123.xml", PodcastPlatform.XIMALAYA),
            ("https://feed.xyzfm.space/abc", PodcastPlatform.XIAOYUZHOU),
            ("https://feeds.megaphone.fm/podcast", PodcastPlatform.GENERIC),
        ]

        for feed_url, expected_platform in test_cases:
            xml_content = self.create_mock_rss_xml(feed_url)

            with patch.object(parser, '_safe_fetch', return_value=(xml_content, None)):
                success, feed, error = await parser.fetch_and_parse_feed(feed_url)

            assert success, f"Failed for {feed_url}"
            assert feed.platform == expected_platform, f"Wrong platform for {feed_url}"

    @pytest.mark.asyncio
    async def test_parser_platform_detection_before_fetch(self, parser, mock_content_validator):
        """Test platform is detected before fetching content"""
        feed_url = "https://www.ximalaya.com/album/123.xml"

        # Mock fetch to verify platform detection happens first
        fetch_called = False

        async def mock_fetch(url):
            nonlocal fetch_called
            fetch_called = True
            return (self.create_mock_rss_xml(url), None)

        with patch.object(parser, '_safe_fetch', side_effect=mock_fetch):
            with patch('app.integration.podcast.secure_rss_parser.PlatformDetector.detect_platform') as mock_detect:
                mock_detect.return_value = PodcastPlatform.XIMALAYA

                success, feed, error = await parser.fetch_and_parse_feed(feed_url)

                # Verify platform detection was called
                mock_detect.assert_called_once_with(feed_url)
                assert fetch_called

    @pytest.mark.asyncio
    async def test_parser_logs_detected_platform(self, parser, mock_content_validator):
        """Test parser logs the detected platform"""
        feed_url = "https://www.ximalaya.com/album/123.xml"
        xml_content = self.create_mock_rss_xml(feed_url)

        with patch.object(parser, '_safe_fetch', return_value=(xml_content, None)):
            with patch('app.integration.podcast.secure_rss_parser.logger') as mock_logger:
                success, feed, error = await parser.fetch_and_parse_feed(feed_url)

                # Verify platform detection was logged
                mock_logger.info.assert_any_call(f"Detected platform: {PodcastPlatform.XIMALAYA}")
