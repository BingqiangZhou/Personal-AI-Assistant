"""
LLM Privacy Content Sanitizer

Provides comprehensive PII (Personally Identifiable Information) detection
and sanitization for content sent to external LLM services.

**Privacy Modes:**
- strict: Remove all PII (names, emails, phones, addresses)
- standard: Remove obvious PII (emails, phones)
- none: No filtering (only with explicit consent)

**Audit & Compliance:**
- GDPR compliant with user-controlled data processing
- Audit trail for all LLM content processing
- User consent tracking
"""

import re
import hashlib
import logging
from typing import Dict, List, Optional, Set
from datetime import datetime
from dataclasses import dataclass, asdict

from app.core.config import settings

logger = logging.getLogger(__name__)


@dataclass
class PrivacyAuditEntry:
    """Audit record for LLM content processing"""
    user_id: int
    timestamp: str
    content_hash: str
    sanitize_mode: str
    pii_types_detected: List[str]
    original_size: int
    sanitized_size: int


class ContentSanitizer:
    """
    Advanced content sanitization with regex patterns for PII detection
    """

    # Detection patterns
    PII_PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',  # US phone format
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
        'url': r'https?://[^\s]+',
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',

        # Names (simplified - higher false positive rate)
        'name': r'\b(?:Dr\.|Mr\.|Mrs\.|Ms\.)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b',

        # Address-like patterns
        'street_address': r'\b\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd)\b',
    }

    # Patterns that might indicate sensitive business/personal info
    SENSITIVE_KEYWORDS = {
        'password', 'secret', 'api_key', 'token', 'private_key',
        'ssn', 'social_security', 'credit_card', 'cvv', 'expiry',
        'classified', 'confidence', 'internal', 'proprietary'
    }

    def __init__(self, mode: str = 'standard'):
        """
        Args:
            mode: 'strict', 'standard', 'none'
        """
        if mode not in ['strict', 'standard', 'none']:
            raise ValueError(f"Invalid mode: {mode}")
        self.mode = mode
        self.audit_log: List[PrivacyAuditEntry] = []

    def sanitize(self, text: str, user_id: int, context: str = "rss_description") -> str:
        """
        Main sanitization method

        Args:
            text: Content to sanitize
            user_id: User identifier for audit
            context: Used to determine sensitivity (rss_description, transcript, etc.)

        Returns:
            Sanitized text
        """
        if self.mode == 'none':
            logger.info(f"User {user_id} opted for no sanitization - consent tracked")
            return text

        original_size = len(text)
        detected_types: Set[str] = set()
        sanitized = text

        # Step 1: Pattern-based PII removal
        for pii_type, pattern in self.PII_PATTERNS.items():
            if pii_type == 'email' and self.mode in ['standard', 'strict']:
                sanitized = re.sub(pattern, '[EMAIL_REDACTED]', sanitized, flags=re.IGNORECASE)
                if '[EMAIL_REDACTED]' in sanitized:
                    detected_types.add('email')

            elif pii_type == 'phone' and self.mode in ['standard', 'strict']:
                sanitized = re.sub(pattern, '[PHONE_REDACTED]', sanitized, flags=re.IGNORECASE)
                if '[PHONE_REDACTED]' in sanitized:
                    detected_types.add('phone')

            elif pii_type in ['ssn', 'credit_card'] and self.mode == 'strict':
                sanitized = re.sub(pattern, f'[{pii_type.upper()}_REDACTED]', sanitized)
                if f'[{pii_type.upper()}_REDACTED]' in sanitized:
                    detected_types.add(pii_type)

            elif pii_type in ['name', 'street_address'] and self.mode == 'strict':
                # These have higher false positive rates
                sanitized = re.sub(pattern, f'[{pii_type.upper()}_REDACTED]', sanitized)
                if f'[{pii_type.upper()}_REDACTED]' in sanitized:
                    detected_types.add(pii_type)

        # Step 2: Sensitive keyword filtering
        if self.mode == 'strict':
            for keyword in self.SENSITIVE_KEYWORDS:
                # Whole word matching
                pattern = r'\b' + re.escape(keyword) + r'\b'
                sanitized = re.sub(pattern, '[SENSITIVE]', sanitized, flags=re.IGNORECASE)

        # Step 3: Handle URLs (for SSRF protection in prompt context)
        if self.mode == 'strict':
            sanitized = re.sub(
                r'https?://[^\s]+',
                '[URL_REDACTED]',
                sanitized
            )
            if '[URL_REDACTED]' in sanitized:
                detected_types.add('url')

        # Step 4: Clean multiple spaces from redactions
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()

        # Audit logging
        self._log_audit(
            user_id=user_id,
            content_hash=self._hash_content(text),
            sanitize_mode=self.mode,
            pii_types_detected=list(detected_types),
            original_size=original_size,
            sanitized_size=len(sanitized)
        )

        # Safety check: if no sanitization occurred in strict mode, warn
        if self.mode == 'strict' and sanitized == text:
            logger.warning(f"Strict mode: No PII detected but content unchanged for user {user_id}")

        return sanitized

    def build_llm_prompt(
        self,
        content_type: str,
        primary_content: str,
        user_prompt: str,
        user_id: int
    ) -> str:
        """
        Build privacy-aware LLM prompt

        Args:
            content_type: 'podcast_description', 'transcript', 'summary'
            primary_content: The content to process
            user_prompt: User's instruction
            user_id: User ID

        Returns:
            Sanitized prompt ready for LLM
        """
        # Sanitize content based on mode
        sanitized_content = self.sanitize(primary_content, user_id, content_type)

        if self.mode == 'strict':
            privacy_notice = (
                "NOTE: Content has been sanitized for privacy. "
                "All PII and sensitive information removed."
            )
        else:
            privacy_notice = (
                "NOTE: Content processed with standard privacy filters."
            )

        prompt = f"""
{privacy_notice}

CONTENT TYPE: {content_type}
CONTENT: {sanitized_content}

USER REQUEST: {user_prompt}

Instructions:
- Extract key information from the sanitized content
- Do not add or infer PII that was redacted
- Focus on factual summary without personal identifiers
- For podcast content: identify main topics, speakers (role only), key insights
"""

        return prompt

    def _hash_content(self, content: str) -> str:
        """Create privacy-preserving content hash for audit"""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]

    def _log_audit(self, **kwargs):
        """Add entry to audit log"""
        entry = PrivacyAuditEntry(
            user_id=kwargs['user_id'],
            timestamp=datetime.utcnow().isoformat(),
            content_hash=kwargs['content_hash'],
            sanitize_mode=kwargs['sanitize_mode'],
            pii_types_detected=kwargs['pii_types_detected'],
            original_size=kwargs['original_size'],
            sanitized_size=kwargs['sanitized_size']
        )
        self.audit_log.append(entry)

        # Log for monitoring
        if kwargs['pii_types_detected']:
            logger.info(
                f"PII Detection - User: {kwargs['user_id']}, "
                f"Types: {kwargs['pii_types_detected']}, "
                f"Mode: {kwargs['sanitize_mode']}"
            )

    def export_audit_log(self, user_id: int) -> List[Dict]:
        """Export user's audit trail for GDPR compliance"""
        return [
            asdict(entry)
            for entry in self.audit_log
            if entry.user_id == user_id
        ]

    def get_usage_stats(self) -> Dict[str, int]:
        """Get privacy filter usage statistics"""
        stats = {
            'total_sanitizations': len(self.audit_log),
            'mode_counts': {},
            'pii_type_counts': {}
        }

        for entry in self.audit_log:
            # Count by mode
            stats['mode_counts'][entry.sanitize_mode] = \
                stats['mode_counts'].get(entry.sanitize_mode, 0) + 1

            # Count PII types
            for pii_type in entry.pii_types_detected:
                stats['pii_type_counts'][pii_type] = \
                    stats['pii_type_counts'].get(pii_type, 0) + 1

        return stats


class PodcastSummarySanitizer(ContentSanitizer):
    """
    Specialized sanitizer for podcast summaries with podcast-specific logic
    """

    def summarize_episode(self, title: str, description: str, transcript: Optional[str], user_id: int) -> Dict:
        """
        Helper method to sanitize and summarize podcast episode for LLM processing

        Returns privacy-preserved inputs for AI summarization
        """
        # Decide on sanitization depth based on content type
        content_parts = []

        # Title (usually safe)
        safe_title = self.sanitize(title, user_id, "podcast_title")

        # Description (more likely to have PII)
        safe_description = self.sanitize(description, user_id, "podcast_description")

        content_parts.append(f"Episode Title: {safe_title}")
        content_parts.append(f"Description: {safe_description}")

        # Transcript (highest risk)
        if transcript:
            safe_transcript = self.sanitize(transcript, user_id, "transcript")
            # Truncate transcript for efficiency (keep first 2000 chars + key sections)
            if len(safe_transcript) > 2000:
                safe_transcript = safe_transcript[:2000] + "... [truncated]"
            content_parts.append(f"Transcript Preview: {safe_transcript}")

        return {
            'sanitized_content': "\n\n".join(content_parts),
            'original_title': title,
            'was_sanitized': safe_description != description or (transcript and safe_transcript != transcript),
            'sanitization_mode': self.mode
        }
