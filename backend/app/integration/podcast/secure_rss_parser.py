"""
Secure RSS Parser for Podcast Subscriptions

This module provides secure RSS/Atom feed parsing with explicit XXE/SSRF protection
and follows the architecture defined in security.py.

**Flow: RSS URL → Security Check → Safe Parse → Database Model**
"""

import logging
from typing import List, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

import aiohttp
from defusedxml.ElementTree import fromstring

from app.core.config import settings
from app.core.llm_privacy import ContentSanitizer
from app.integration.podcast.security import PodcastSecurityValidator, PodcastContentValidator
from app.integration.podcast.platform_detector import PlatformDetector

logger = logging.getLogger(__name__)


@dataclass
class PodcastEpisode:
    """Structured podcast episode data"""
    title: str
    description: str
    audio_url: str
    published_at: datetime
    duration: Optional[int] = None
    transcript_url: Optional[str] = None
    guid: Optional[str] = None
    image_url: Optional[str] = None
    link: Optional[str] = None  # <item><link> 标签，分集详情页链接


@dataclass
class PodcastFeed:
    """Structured podcast feed data"""
    title: str
    link: str
    description: str
    episodes: List[PodcastEpisode]
    last_fetched: datetime
    author: Optional[str] = None
    language: Optional[str] = None
    categories: List[str] = None
    explicit: Optional[bool] = None
    image_url: Optional[str] = None
    podcast_type: Optional[str] = None
    platform: Optional[str] = None


class SecureRSSParser:
    """
    Secure parser with complete validation pipeline
    """

    def __init__(self, user_id: int):
        self.user_id = user_id
        self.security = PodcastSecurityValidator()
        self.privacy = ContentSanitizer(mode=settings.LLM_CONTENT_SANITIZE_MODE)

    async def fetch_and_parse_feed(self, feed_url: str) -> Tuple[bool, Optional[PodcastFeed], Optional[str]]:
        """
        Complete pipeline: fetch → validate → parse

        Returns:
            Tuple[success, feed_data, error_message]
        """
        logger.info(f"User {self.user_id}: Fetching RSS from {feed_url}")

        # Step 0: Detect platform
        platform = PlatformDetector.detect_platform(feed_url)
        logger.info(f"Detected platform: {platform}")

        # Step 1: Validate URL
        valid_url, url_error = self.security.validate_audio_url(feed_url)
        if not valid_url:
            logger.warning(f"Invalid RSS URL: {url_error}")
            return False, None, f"Invalid URL: {url_error}"

        # Step 2: Fetch content
        xml_content, fetch_error = await self._safe_fetch(feed_url)
        if fetch_error:
            return False, None, fetch_error

        # Step 3: Security validation
        validator = PodcastContentValidator()
        validation_result = await validator.validate_rss_feed(feed_url, xml_content)
        if not validation_result['valid']:
            logger.warning(f"Feed validation failed: {validation_result['error']}")
            return False, None, validation_result['error']

        # Step 4: Parse safely
        try:
            feed = await self._parse_feed_securely(feed_url, xml_content, platform)
            logger.info(f"Successfully parsed feed: {feed.title} with {len(feed.episodes)} episodes from {platform}")
            return True, feed, None
        except Exception as e:
            logger.error(f"Parsing error: {e}")
            return False, None, f"Failed to parse feed: {e}"

    async def _safe_fetch(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Fetch with size and timeout limits"""
        try:
            timeout = aiohttp.ClientTimeout(total=60, connect=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers={
                    'User-Agent': 'PersonalAI-Assistant/1.0 (+https://github.com/user/repo)'
                }) as resp:
                    if resp.status != 200:
                        return None, f"HTTP {resp.status}"

                    # Check size before reading
                    size = int(resp.headers.get('Content-Length', 0))
                    if size > self.security.MAX_RSS_SIZE:
                        return None, f"Feed too large: {size} bytes"

                    content = await resp.read()
                    if len(content) > self.security.MAX_RSS_SIZE:
                        return None, "Content exceeds size limit"

                    # Decode content as text
                    try:
                        text_content = content.decode('utf-8')
                    except UnicodeDecodeError:
                        # Try other common encodings
                        try:
                            text_content = content.decode('latin-1')
                        except UnicodeDecodeError:
                            text_content = content.decode('utf-8', errors='ignore')

                    return text_content, None

        except aiohttp.ClientError as e:
            logger.error(f"Fetch error: {e}")
            return None, f"Could not fetch feed: {e}"

    async def _parse_feed_securely(self, feed_url: str, xml_content: str, platform: str) -> PodcastFeed:
        """Parse RSS with defusedxml"""
        root = fromstring(xml_content)

        # Basic feed info
        channel = root.find('channel') if root.tag == 'rss' else root
        if channel is None:
            raise ValueError("Invalid RSS structure")

        title = self._safe_text(channel.findtext('title', 'Unknown'))
        link = self._safe_text(channel.findtext('link', ''))
        description = self._sanitize_description(channel.findtext('description', ''))

        # Extract iTunes namespace information
        itunes_ns = {'itunes': 'http://www.itunes.com/dtds/podcast-1.0.dtd'}

        # Author
        author = self._safe_text(channel.findtext('itunes:author', '', namespaces=itunes_ns))

        # Language
        language = self._safe_text(channel.findtext('language', ''))

        # Categories
        categories = []
        for category in channel.findall('itunes:category', namespaces=itunes_ns):
            if category.get('text'):
                categories.append(category.get('text'))

        # Explicit content
        explicit_text = self._safe_text(channel.findtext('itunes:explicit', '', namespaces=itunes_ns))
        explicit = explicit_text.lower() == 'true' if explicit_text else None

        # Podcast image
        image_element = channel.find('itunes:image', namespaces=itunes_ns)
        image_url = image_element.get('href') if image_element is not None else None

        # Podcast type
        podcast_type = self._safe_text(channel.findtext('itunes:type', '', namespaces=itunes_ns))

        # Parse episodes - parse all available episodes
        episodes = []

        for item in channel.findall('item'):
            episode = self._parse_episode(item)
            if episode:
                episodes.append(episode)

        # Use latest episode's published time as last_fetched, fallback to current time
        last_fetched = episodes[0].published_at if episodes else datetime.utcnow()

        return PodcastFeed(
            title=title,
            link=link,
            description=description,
            episodes=episodes,
            last_fetched=last_fetched,
            author=author or None,
            language=language or None,
            categories=categories or None,
            explicit=explicit,
            image_url=image_url,
            podcast_type=podcast_type or None,
            platform=platform
        )

    def _parse_episode(self, item) -> Optional[PodcastEpisode]:
        """Parse a single episode item"""
        try:
            # Namespaces for iTunes and other extensions
            itunes_ns = {'itunes': 'http://www.itunes.com/dtds/podcast-1.0.dtd'}

            # Title (safe)
            title = self._safe_text(item.findtext('title', 'Untitled'))

            # Description - prefer content:encoded over description, use raw HTML without sanitization
            content_encoded = item.findtext('content:encoded', '', namespaces={'content': 'http://purl.org/rss/1.0/modules/content/'})
            raw_desc = content_encoded or item.findtext('description', '')
            description = raw_desc if raw_desc else ''  # Use raw HTML directly

            # Extract image URL from description or iTunes namespace
            episode_image_url = None

            # First, try to extract from iTunes:image namespace
            episode_image = item.find('itunes:image', namespaces=itunes_ns)
            if episode_image is not None:
                episode_image_url = episode_image.get('href')

            # If no iTunes image, try to extract from description (for xyzfm and other platforms)
            if not episode_image_url:
                episode_image_url = self._extract_first_image_from_text(raw_desc)

            # Published date
            pub_date = item.findtext('pubDate')
            published_at = self._parse_date(pub_date)

            # Find enclosure (audio)
            enclosure = item.find('enclosure')
            if enclosure is None:
                return None  # Not a podcast episode

            audio_url = enclosure.get('url')
            if not audio_url:
                return None

            # Get audio file size from enclosure
            audio_file_size = enclosure.get('length')
            audio_size = int(audio_file_size) if audio_file_size and audio_file_size.isdigit() else None

            # Validate audio URL
            valid, error = self.security.validate_audio_url(audio_url)
            if not valid:
                logger.warning(f"Invalid audio URL in episode {title}: {error}")
                return None

            # Duration
            duration_text = item.findtext('itunes:duration', None, namespaces=itunes_ns)
            duration = self._parse_duration(duration_text)

            # Transcript URL (if available)
            transcript_url = None
            # Check for podcast namespace transcript
            transcript_element = item.find('podcast:transcript', namespaces={'podcast': 'https://podcastindex.org/namespace/1.0'})
            if transcript_element is not None:
                transcript_url = transcript_element.get('url')
            # Also check for simple transcript URL in custom element
            if not transcript_url:
                transcript_text = item.findtext('transcript_url')
                if transcript_text:
                    transcript_url = transcript_text

            # GUID
            guid_element = item.find('guid')
            guid = guid_element.text if guid_element is not None else f"{title}-{published_at.isoformat()}"
            guid_is_permalink = guid_element.get('isPermaLink', 'true') if guid_element is not None else 'true'

            # Item link (episode detail page link)
            # 先尝试直接获取
            link_element = item.find('link')
            raw_link = link_element.text if link_element is not None else None

            # Debug: 记录原始 link 值
            logger.debug(f"🔗 [PARSER] Episode: {title[:50]}...")
            logger.debug(f"   - raw link element: {link_element}")
            logger.debug(f"   - raw link text: {repr(raw_link)}")

            # 清理 link
            item_link = self._safe_text(raw_link) if raw_link else None
            logger.debug(f"   - cleaned item_link: {repr(item_link)}")

            return PodcastEpisode(
                title=title,
                description=description,
                audio_url=audio_url,
                published_at=published_at,
                duration=duration,
                transcript_url=transcript_url,
                guid=guid,
                image_url=episode_image_url,
                link=item_link if item_link else None
            )

        except Exception as e:
            logger.error(f"Error parsing episode: {e}")
            return None

    def _safe_text(self, text: Optional[str]) -> str:
        """Clean and truncate text"""
        if not text:
            return ""
        # Remove null bytes and control characters
        text = text.replace('\x00', '').replace('\r', '')
        return text.strip()[:500]  # Limit length

    def _sanitize_description(self, text: Optional[str]) -> str:
        """
        Sanitize description for podcast episodes.

        For HTML content (shownotes):
        - Apply security cleaning (remove dangerous tags/attributes)
        - Skip privacy filtering (public content, don't break HTML links)

        Privacy filtering is designed for transcripts/AI summaries, not public shownotes.
        """
        if not text:
            return ""

        # Only apply HTML security cleaning (XSS protection)
        # Skip privacy filtering to preserve HTML structure and links
        clean_text = self.security.sanitize_html_content(text)

        # Truncate to reasonable length
        return clean_text[:5000]  # Increased from 1000 to 5000 for HTML content

    def _parse_date(self, date_str: Optional[str]) -> datetime:
        """Parse various date formats"""
        if not date_str:
            return datetime.utcnow()
        try:
            # Handle RFC 2822 format (common in RSS)
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except:
            return datetime.utcnow()

    def _parse_duration(self, duration_text: Optional[str]) -> Optional[int]:
        """Parse duration text to seconds"""
        if not duration_text:
            return None

        try:
            # Format: HH:MM:SS or MMM:SS or seconds
            if ':' in duration_text:
                parts = duration_text.split(':')
                if len(parts) == 3:  # HH:MM:SS
                    return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
                elif len(parts) == 2:  # MM:SS
                    return int(parts[0]) * 60 + int(parts[1])
            else:
                return int(duration_text)
        except:
            return None

    def _extract_first_image_from_text(self, text: str) -> Optional[str]:
        """Extract the first image URL from text using regex patterns"""
        if not text:
            return None

        import re

        # Pattern 1: Markdown images: ![alt](url)
        markdown_pattern = r'!\[.*?\]\((https?://[^\s\)]+)\)'
        markdown_match = re.search(markdown_pattern, text)
        if markdown_match:
            url = markdown_match.group(1)
            # Validate URL
            if self._is_valid_image_url(url):
                return url

        # Pattern 2: HTML img tags: <img src="url" ...>
        html_pattern = r'<img[^>]+src=["\'](https?://[^"\']+)["\']'
        html_match = re.search(html_pattern, text, re.IGNORECASE)
        if html_match:
            url = html_match.group(1)
            # Validate URL
            if self._is_valid_image_url(url):
                return url

        # Pattern 3: Plain image URLs (standalone URLs ending with image extensions)
        url_pattern = r'(https?://[^\s]+\.(?:jpg|jpeg|png|gif|webp)(?:\?[^\s]*)?)'
        url_match = re.search(url_pattern, text, re.IGNORECASE)
        if url_match:
            url = url_match.group(1)
            # Validate URL
            if self._is_valid_image_url(url):
                return url

        return None

    def _is_valid_image_url(self, url: str) -> bool:
        """Check if URL is a valid image URL"""
        if not url:
            return False

        # Basic URL validation
        if not url.startswith(('http://', 'https://')):
            return False

        # Check for common image file extensions
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg']
        url_lower = url.lower()

        # Either ends with image extension or contains image-like patterns
        has_extension = any(url_lower.endswith(ext) for ext in image_extensions)
        has_image_keywords = any(keyword in url_lower for keyword in ['image', 'img', 'photo', 'pic', 'cover'])

        return has_extension or has_image_keywords


class PodcastValidationHelper:
    """
    Helper functions for subscription management
    """

    @staticmethod
    async def test_subscription(feed_url: str, user_id: int) -> dict:
        """Test if a feed URL is valid and create subscription info"""
        parser = SecureRSSParser(user_id)
        success, feed, error = await parser.fetch_and_parse_feed(feed_url)

        if not success:
            return {'valid': False, 'error': error}

        return {
            'valid': True,
            'title': feed.title,
            'description': feed.description,
            'link': feed.link,
            'episode_count': len(feed.episodes),
            'latest_episode': feed.episodes[0].title if feed.episodes else None,
            'requires_ai_summary': True
        }

    @staticmethod
    def generate_subscription_summary(feed: PodcastFeed) -> str:
        """Generate safe summary for user preview"""
        episode_summaries = []

        for ep in feed.episodes[:5]:  # Preview top 5
            safe_title = ep.title.replace('\n', ' ').strip()[:100]
            safe_desc = ep.description.replace('\n', ' ').strip()[:200] + "..."
            duration_str = f"{ep.duration//60}min" if ep.duration else "N/A"
            episode_summaries.append(f"• {safe_title} ({duration_str}): {safe_desc}")

        return f"""Podcast: {feed.title}

Description: {feed.description[:200]}

Recent Episodes:
{''.join(episode_summaries)}
"""
