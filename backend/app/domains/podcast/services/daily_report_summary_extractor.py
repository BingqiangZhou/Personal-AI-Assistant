"""Helpers for extracting one-line summaries from podcast AI summary text."""

from __future__ import annotations

import re


_SECTION_HEADING_RE = re.compile(
    r"^\s*##\s*(?:1[\.\)]\s*)?(?:一句话摘要|Executive Summary)(?:\s*/\s*(?:一句话摘要|Executive Summary))?\s*$",
    re.IGNORECASE | re.MULTILINE,
)
_NEXT_HEADING_RE = re.compile(r"^\s*##\s+", re.MULTILINE)
_LEADING_BULLET_RE = re.compile(r"^\s*(?:[-*]\s+|\d+[\.\)]\s+)")
_WHITESPACE_RE = re.compile(r"\s+")
_SENTENCE_RE = re.compile(r"[^。！？!?\.]+[。！？!?\.]?")


def extract_one_line_summary(ai_summary: str | None) -> str | None:
    """Extract one line summary from AI summary markdown text."""
    if not ai_summary:
        return None

    section_text = _extract_executive_summary_section(ai_summary)
    if section_text:
        sentence = _extract_first_sentence(section_text)
        if sentence:
            return sentence

    return _extract_first_sentence(ai_summary)


def _extract_executive_summary_section(summary_text: str) -> str | None:
    heading_match = _SECTION_HEADING_RE.search(summary_text)
    if not heading_match:
        return None

    section_start = heading_match.end()
    remaining = summary_text[section_start:]
    next_heading_match = _NEXT_HEADING_RE.search(remaining)
    if next_heading_match:
        section_body = remaining[: next_heading_match.start()]
    else:
        section_body = remaining

    normalized = _WHITESPACE_RE.sub(" ", section_body).strip()
    return normalized or None


def _extract_first_sentence(text: str) -> str | None:
    if not text:
        return None

    normalized = _WHITESPACE_RE.sub(" ", text).strip()
    if not normalized:
        return None

    matches = _SENTENCE_RE.findall(normalized)
    for raw_sentence in matches:
        sentence = _LEADING_BULLET_RE.sub("", raw_sentence).strip()
        sentence = sentence.strip("#").strip()
        if sentence:
            return sentence[:280]

    return None
