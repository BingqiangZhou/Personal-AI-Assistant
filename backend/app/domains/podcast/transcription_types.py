"""Shared transcription enums and lightweight contracts."""

from enum import Enum


class ScheduleFrequency(str, Enum):
    """Task scheduling frequency."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MANUAL = "manual"
