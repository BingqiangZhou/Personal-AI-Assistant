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


@dataclass
class PodcastFeed:
    """Structured podcast feed data"""
    title: str
    link: str
    description: str
    episodes: List[PodcastEpisode]
    last_fetched: datetime


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
            feed = await self._parse_feed_securely(feed_url, xml_content)
            logger.info(f"Successfully parsed feed: {feed.title} with {len(feed.episodes)} episodes")
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

                    content = await resp.read(charset='utf-8')
                    if len(content) > self.security.MAX_RSS_SIZE:
                        return None, "Content exceeds size limit"

                    return content, None

        except aiohttp.ClientError as e:
            logger.error(f"Fetch error: {e}")
            return None, f"Could not fetch feed: {e}"

    async def _parse_feed_securely(self, feed_url: str, xml_content: str) -> PodcastFeed:
        """Parse RSS with defusedxml"""
        root = fromstring(xml_content)

        # Basic feed info
        channel = root.find('channel') if root.tag == 'rss' else root
        if channel is None:
            raise ValueError("Invalid RSS structure")

        title = self._safe_text(channel.findtext('title', 'Unknown'))
        link = self._safe_text(channel.findtext('link', ''))
        description = self._sanitize_description(channel.findtext('description', ''))

        # Parse episodes
        episodes = []
        item_count = 0

        for item in channel.findall('item'):
            if item_count >= 20:  # Limit initial fetch
                break

            episode = self._parse_episode(item)
            if episode:
                episodes.append(episode)
                item_count += 1

        return PodcastFeed(
            title=title,
            link=link,
            description=description,
            episodes=episodes,
            last_fetched=datetime.utcnow()
        )

    def _parse_episode(self, item) -> Optional[PodcastEpisode]:
        """Parse a single episode item"""
        try:
            # Title (safe)
            title = self._safe_text(item.findtext('title', 'Untitled'))

            # Description (sanitize)
            raw_desc = item.findtext('description', '')
            description = self._sanitize_description(raw_desc)

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

            # Validate audio URL
            valid, error = self.security.validate_audio_url(audio_url)
            if not valid:
                logger.warning(f"Invalid audio URL in episode {title}: {error}")
                return None

            # Optional: duration
            duration_text = item.findtext('itunes:duration', None, namespaces={'itunes': 'http://www.itunes.com/dtds/podcast-1.0.dtd'})
            duration = self._parse_duration(duration_text)

            # Optional: transcript
            transcript_url = None
            transcript_ref = item.find('podcast:transcript', namespaces={'podcast': 'https://podcastindex.org/namespace/1.0'})
            if transcript_ref is not None:
                transcript_url = transcript_ref.get('url')

            # GUID
            guid = item.findtext('guid', None)

            return PodcastEpisode(
                title=title,
                description=description,
                audio_url=audio_url,
                published_at=published_at,
                duration=duration,
                transcript_url=transcript_url,
                guid=guid
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
        """Sanitize description using privacy system"""
        if not text:
            return ""
        # Clean HTML first
        clean_text = self.security.sanitize_html_content(text)
        # Then apply privacy filters
        sanitized = self.privacy.sanitize(clean_text, self.user_id, "podcast_description")
        return sanitized[:1000]  # Truncate

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
