"""Helpers for extracting one-line summaries from podcast AI summary text."""

from __future__ import annotations

import re


_HEADING_PREFIX_RE = re.compile(
    r"^\s*(?:#{1,6}\s*|(?:\d+(?:\.\d+)*|[一二三四五六七八九十]+)\s*[\.\)\]、:：]\s*)",
    re.IGNORECASE,
)
_EXEC_SUMMARY_KEYWORD_RE = re.compile(
    r"(?:一句话摘要|Executive Summary)",
    re.IGNORECASE,
)
_MARKDOWN_HEADING_RE = re.compile(r"^\s*#{1,6}\s+\S", re.IGNORECASE)
_NUMBERED_HEADING_RE = re.compile(
    r"^\s*(?:\d+(?:\.\d+)*|[一二三四五六七八九十]+)\s*[\.\)\]、:：]\s+\S",
    re.IGNORECASE,
)
_LEADING_BULLET_RE = re.compile(r"^\s*(?:[-*]\s+|\d+[\.\)]\s+)")
_WHITESPACE_RE = re.compile(r"\s+")
_SENTENCE_RE = re.compile(r"[^。！？!?\.]+[。！？!?\.]?")


def extract_one_line_summary(ai_summary: str | None) -> str | None:
    """Extract one line summary from AI summary markdown text."""
    if not ai_summary:
        return None

    section_text = _extract_executive_summary_section(ai_summary)
    if section_text:
        return section_text

    return _extract_first_sentence(ai_summary)


def _extract_executive_summary_section(summary_text: str) -> str | None:
    section_start = _find_executive_summary_section_start(summary_text)
    if section_start is None:
        return None

    section_end = _find_next_section_heading_start(summary_text, section_start)
    section_body = summary_text[section_start:section_end]

    normalized = _WHITESPACE_RE.sub(" ", section_body).strip()
    return normalized or None


def _find_executive_summary_section_start(summary_text: str) -> int | None:
    line_start = 0
    for line in summary_text.splitlines(keepends=True):
        line_end = line_start + len(line)
        if _is_executive_summary_heading(line):
            return line_end
        line_start = line_end
    return None


def _find_next_section_heading_start(summary_text: str, section_start: int) -> int:
    line_start = section_start
    for line in summary_text[section_start:].splitlines(keepends=True):
        line_end = line_start + len(line)
        if _is_next_section_heading(line):
            return line_start
        line_start = line_end
    return len(summary_text)


def _is_executive_summary_heading(line: str) -> bool:
    text = line.strip()
    if not text:
        return False
    if not _HEADING_PREFIX_RE.match(text):
        return False
    return bool(_EXEC_SUMMARY_KEYWORD_RE.search(text))


def _is_next_section_heading(line: str) -> bool:
    text = line.strip()
    if not text:
        return False
    if _is_executive_summary_heading(line):
        return False
    return bool(
        _MARKDOWN_HEADING_RE.match(text)
        or _NUMBERED_HEADING_RE.match(text)
    )


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
