from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.domains.podcast.services.daily_report_service import DailyReportService
from app.domains.podcast.services.daily_report_summary_extractor import (
    extract_one_line_summary,
)


class _ScalarOneOrNoneResult:
    def __init__(self, value):
        self._value = value

    def scalar_one_or_none(self):
        return self._value


@pytest.mark.asyncio
async def test_compute_window_utc_for_shanghai_day():
    service = DailyReportService(db=AsyncMock(), user_id=1)
    window_start, window_end = service._compute_window_utc(date(2026, 2, 20))

    assert window_start == datetime(2026, 2, 19, 16, 0, tzinfo=timezone.utc)
    assert window_end == datetime(2026, 2, 20, 16, 0, tzinfo=timezone.utc)


def test_extract_one_line_summary_prefers_executive_section():
    summary = """
## 1. 一句话摘要
- 这是应当被抽取的一句话。后面的内容不应优先。

## 2. 详细要点
- A
"""
    result = extract_one_line_summary(summary)

    assert result == "这是应当被抽取的一句话。"


def test_extract_one_line_summary_falls_back_to_first_sentence():
    summary = "没有专门段落时，直接取第一句。第二句不要优先。"
    result = extract_one_line_summary(summary)

    assert result == "没有专门段落时，直接取第一句。"


@pytest.mark.asyncio
async def test_generate_daily_report_triggers_async_processing_for_unsummarized():
    db = AsyncMock()
    service = DailyReportService(db=db, user_id=1)
    report = SimpleNamespace(id=10, generated_at=None, total_items=0)
    unsummarized_episode = SimpleNamespace(id=101)

    service._get_or_create_report = AsyncMock(return_value=report)
    service._list_window_summarized_episodes = AsyncMock(return_value=[])
    service._list_carryover_summarized_episodes = AsyncMock(return_value=[])
    service._list_window_unsummarized_episodes = AsyncMock(
        return_value=[unsummarized_episode]
    )
    service._trigger_episode_processing = AsyncMock()
    service._append_item_if_needed = AsyncMock(return_value=0)
    service._count_report_items = AsyncMock(return_value=0)
    service.get_daily_report = AsyncMock(return_value={"available": True})

    result = await service.generate_daily_report(target_date=date(2026, 2, 20))

    assert result == {"available": True}
    service._trigger_episode_processing.assert_awaited_once_with(101)
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_generate_daily_report_marks_carryover_items():
    db = AsyncMock()
    service = DailyReportService(db=db, user_id=1)
    report = SimpleNamespace(id=9, generated_at=None, total_items=0)
    carryover_episode = SimpleNamespace(id=202)

    service._get_or_create_report = AsyncMock(return_value=report)
    service._list_window_summarized_episodes = AsyncMock(return_value=[])
    service._list_carryover_summarized_episodes = AsyncMock(
        return_value=[carryover_episode]
    )
    service._list_window_unsummarized_episodes = AsyncMock(return_value=[])
    service._trigger_episode_processing = AsyncMock()
    service._append_item_if_needed = AsyncMock(return_value=1)
    service._count_report_items = AsyncMock(return_value=1)
    service.get_daily_report = AsyncMock(return_value={"available": True})

    await service.generate_daily_report(target_date=date(2026, 2, 21))

    service._append_item_if_needed.assert_awaited_once_with(
        report,
        carryover_episode,
        is_carryover=True,
    )


@pytest.mark.asyncio
async def test_append_item_if_needed_does_not_duplicate_episode():
    db = AsyncMock()
    db.add = Mock()
    db.flush = AsyncMock()
    db.execute = AsyncMock(
        side_effect=[
            _ScalarOneOrNoneResult(None),
            _ScalarOneOrNoneResult(1),
        ]
    )
    service = DailyReportService(db=db, user_id=1)
    now = datetime.now(timezone.utc)

    report = SimpleNamespace(id=7)
    episode = SimpleNamespace(
        id=88,
        subscription_id=2,
        title="Episode 88",
        subscription=SimpleNamespace(title="Podcast X"),
        ai_summary="## 1. 一句话摘要\n- 首句摘要。",
        created_at=now,
        published_at=now,
    )

    added_first = await service._append_item_if_needed(
        report,
        episode,
        is_carryover=True,
    )
    added_second = await service._append_item_if_needed(
        report,
        episode,
        is_carryover=True,
    )

    assert added_first == 1
    assert added_second == 0
    assert db.add.call_count == 1
