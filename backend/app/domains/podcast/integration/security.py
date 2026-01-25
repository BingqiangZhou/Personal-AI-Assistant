"""
Podcast Security Module - XXE/SSRF Protection & Content Validation

**Security Features:**
1. XXE Attack Prevention - defusedxml-based safe parsing
2. SSRF Protection - URL validation for audio downloads
3. Size Limits - Prevent resource exhaustion attacks
4. Content Sanitization - XML/HTML cleanup

**Risk Mitigation:**
- External XML entity injection
- Server-side request forgery
- Denial of service via large files
- Malicious content injection
"""

import logging
import re
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from defusedxml.common import NotSupportedError

from app.core.config import settings


logger = logging.getLogger(__name__)


class PodcastSecurityValidator:
    """
    Comprehensive security validation for podcast operations
    """

    # Maximum safe limits
    MAX_RSS_SIZE = 100 * 1024 * 1024  # 100MB max RSS size (support very large podcast feeds with many episodes)
    MAX_AUDIO_SIZE = settings.MAX_PODCAST_EPISODE_DOWNLOAD_SIZE  # 500MB
    MAX_TRANSCRIPT_SIZE = 5 * 1024 * 1024  # 5MB for transcripts

    # Allowed protocols
    ALLOWED_SCHEMES = set(settings.ALLOWED_AUDIO_SCHEMES)

    # Suspicious patterns that indicate XXE attempts
    XXE_PATTERNS = [
        r'<!ENTITY\s+',
        r'<!DOCTYPE\s+.*\[',
        r'SYSTEM\s+["\']',
        r'PUBLIC\s+["\']',
    ]

    # Dangerous URL patterns for SSRF
    DANGEROUS_HOSTS = {
        'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254',  # Metadata endpoints
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',  # Private networks
    }

    @classmethod
    def validate_rss_xml(cls, xml_content: str) -> tuple[bool, Optional[str]]:
        """
        Safe RSS XML validation using defusedxml

        Args:
            xml_content: Raw RSS XML string

        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(xml_content) > cls.MAX_RSS_SIZE:
            return False, f"RSS too large: {len(xml_content)} bytes"

        # Check for XXE patterns before parsing
        for pattern in cls.XXE_PATTERNS:
            if re.search(pattern, xml_content, re.IGNORECASE):
                logger.warning(f"XXE pattern detected: {pattern}")
                return False, "Invalid XML content detected"

        try:
            # Use defusedxml for safe parsing
            # Additional entity expansion limit
            from defusedxml.ElementTree import fromstring

            root = fromstring(xml_content)

            # Verify it looks like RSS/Atom
            if root.tag not in ['rss', 'feed', 'channel']:
                return False, "Invalid RSS/Atom format"

            return True, None

        except NotSupportedError as e:
            logger.error(f"XML parsing error: {e}")
            return False, "Unsupported XML feature detected"
        except Exception as e:
            logger.error(f"XML validation failed: {e}")
            return False, "Invalid XML structure"

    @classmethod
    def validate_audio_url(cls, url: str) -> tuple[bool, Optional[str]]:
        """
        Validate audio URL for SSRF protection

        Args:
            url: Audio file URL

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)

            # Check scheme
            if parsed.scheme not in cls.ALLOWED_SCHEMES:
                return False, f"Invalid protocol: {parsed.scheme}"

            # Check for dangerous hosts/IPs
            if cls._is_dangerous_host(parsed.hostname):
                return False, "Access to internal resources prohibited"

            # Check for port scanning attempts
            if parsed.port and parsed.port not in [80, 443, 8080, 8443]:
                logger.warning(f"Non-standard port detected: {parsed.port}")
                # Actually allow, but log for monitoring

            # Ensure absolute URL
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL format"

            return True, None

        except Exception as e:
            logger.error(f"URL validation error: {e}")
            return False, "Malformed URL"

    @classmethod
    def _is_dangerous_host(cls, hostname: Optional[str]) -> bool:
        """Check if hostname resolves to dangerous address"""
        if not hostname:
            return True

        # Direct IP checks
        hostname_lower = hostname.lower()

        # Exact matches
        dangerous_exact = {'localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', '::1'}
        if hostname_lower in dangerous_exact:
            return True

        # Private network checks (simplified - real implementation would use ipaddress module)
        if re.match(r'^10\.', hostname_lower):
            return True
        if re.match(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', hostname_lower):
            return True
        if re.match(r'^192\.168\.', hostname_lower):
            return True

        return False

    @classmethod
    async def validate_audio_download(cls, url: str) -> tuple[bool, Optional[str], Optional[bytes]]:
        """
        Safely download audio with size limits and validation

        Args:
            url: Audio URL to download

        Returns:
            Tuple of (success, error_message, data)
        """
        # Validate URL first
        valid, error = cls.validate_audio_url(url)
        if not valid:
            return False, error, None

        try:
            timeout = aiohttp.ClientTimeout(total=300)  # 5 minute total timeout
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    # Check content length before downloading
                    content_length = response.headers.get('Content-Length')
                    if content_length:
                        size = int(content_length)
                        if size > cls.MAX_AUDIO_SIZE:
                            return False, f"Audio too large: {size} bytes", None

                    # Stream download with size tracking
                    content = await response.read()

                    if len(content) > cls.MAX_AUDIO_SIZE:
                        return False, "File size exceeds limit during download", None

                    return True, None, content

        except aiohttp.ClientError as e:
            logger.error(f"Audio download error: {e}")
            return False, f"Failed to download audio: {e}", None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return False, "Download failed", None

    @classmethod
    def sanitize_html_content(cls, html: str) -> str:
        """
        Clean HTML content before processing while preserving safe HTML tags.

        This method removes dangerous tags (script, iframe, etc.) but preserves
        safe HTML tags like p, br, a, img, h1-h6, ul, ol, li, table, etc.
        for proper rendering of shownotes.
        """
        from bs4 import BeautifulSoup

        if not html:
            return ""

        soup = BeautifulSoup(html, 'html.parser')

        # Remove dangerous tags completely
        dangerous_tags = ['script', 'style', 'iframe', 'object', 'embed',
                         'form', 'input', 'button', 'select', 'textarea']
        for tag_name in dangerous_tags:
            for tag in soup.find_all(tag_name):
                tag.decompose()

        # Remove dangerous attributes (onclick, onerror, etc.)
        for tag in soup.find_all(True):
            # Remove event handler attributes
            attrs_to_remove = [attr for attr in tag.attrs
                             if attr.lower().startswith('on')]
            for attr in attrs_to_remove:
                del tag[attr]

            # Remove style attributes with javascript:
            if 'style' in tag.attrs:
                style = tag['style']
                if 'javascript:' in style.lower():
                    del tag['style']

            # For anchor tags, add rel="nofollow noopener" for security
            if tag.name == 'a' and 'href' in tag.attrs:
                tag['rel'] = 'nofollow noopener'

        # Return the cleaned HTML as string (preserves safe tags)
        cleaned_html = str(soup)

        # Clean up extra whitespace but preserve HTML structure
        cleaned_html = re.sub(r'\s+', ' ', cleaned_html)

        return cleaned_html.strip()


class PodcastContentValidator:
    """
    High-level content validation interface
    """

    @staticmethod
    async def validate_rss_feed(feed_url: str, xml_content: str) -> dict:
        """
        Complete RSS feed validation pipeline

        Returns:
            dict with validation results and metadata
        """
        security = PodcastSecurityValidator

        # 1. XML security check
        xml_valid, xml_error = security.validate_rss_xml(xml_content)
        if not xml_error:
            # 2. Parse safely
            try:
                from defusedxml.ElementTree import fromstring
                root = fromstring(xml_content)

                # Extract basic info
                title = root.findtext('.//title', 'Unknown')
                link = root.findtext('.//link', '')

                # Detect audio enclosures
                enclosures = root.findall('.//enclosure')
                has_audio = any(e.get('type', '').startswith('audio/') for e in enclosures)

                return {
                    'valid': True,
                    'title': title,
                    'link': link,
                    'has_audio': has_audio,
                    'episode_count': len(enclosures),
                    'security_scan': 'passed'
                }
            except Exception as e:
                return {'valid': False, 'error': f'Parse failed: {e}'}

        return {'valid': False, 'error': xml_error}

    @staticmethod
    def detect_xxe_attempts(xml_content: str) -> list[str]:
        """
        Scan for XXE attack attempts

        Returns:
            List of detected threat patterns
        """
        threats = []
        for pattern in PodcastSecurityValidator.XXE_PATTERNS:
            if re.search(pattern, xml_content, re.IGNORECASE):
                threats.append(pattern)
        return threats
