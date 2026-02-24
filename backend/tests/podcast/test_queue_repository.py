"""Queue repository behavior tests for queue invariants and compaction."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from app.domains.podcast.models import PodcastQueueItem
from app.domains.podcast.repositories import PodcastRepository


def _queue_item(item_id: int, episode_id: int, position: int) -> SimpleNamespace:
    return SimpleNamespace(
        id=item_id,
        episode_id=episode_id,
        position=position,
        episode=SimpleNamespace(subscription=None),
    )


def _queue_with_items(
    items: list[SimpleNamespace],
    *,
    current_episode_id: int | None,
    revision: int = 0,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=1,
        user_id=1,
        items=items,
        current_episode_id=current_episode_id,
        revision=revision,
        updated_at=None,
    )


def _mock_db() -> SimpleNamespace:
    return SimpleNamespace(
        add=Mock(),
        flush=AsyncMock(),
        commit=AsyncMock(),
        delete=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_add_or_move_to_tail_adds_new_item_without_full_rewrite() -> None:
    db = _mock_db()
    repo = PodcastRepository(db=db, redis=AsyncMock())
    queue = _queue_with_items(
        [_queue_item(item_id=1, episode_id=10, position=0)],
        current_episode_id=10,
    )

    repo.get_queue_with_items = AsyncMock(side_effect=[queue, queue])
    repo._rewrite_queue_positions = AsyncMock()

    result = await repo.add_or_move_to_tail(user_id=1, episode_id=11, max_items=500)

    assert result is queue
    assert db.add.call_count == 1
    added_item = db.add.call_args.args[0]
    assert isinstance(added_item, PodcastQueueItem)
    assert added_item.episode_id == 11
    assert added_item.position == repo._queue_position_step
    assert queue.current_episode_id == 10
    repo._rewrite_queue_positions.assert_not_awaited()
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_add_or_move_to_tail_keeps_current_episode_at_head() -> None:
    db = _mock_db()
    repo = PodcastRepository(db=db, redis=AsyncMock())
    head = _queue_item(item_id=1, episode_id=10, position=0)
    tail = _queue_item(item_id=2, episode_id=11, position=repo._queue_position_step)
    queue = _queue_with_items([head, tail], current_episode_id=10)

    repo.get_queue_with_items = AsyncMock(side_effect=[queue, queue])
    repo._rewrite_queue_positions = AsyncMock()

    await repo.add_or_move_to_tail(user_id=1, episode_id=10, max_items=500)

    assert head.position == 0
    assert db.add.call_count == 0
    repo._rewrite_queue_positions.assert_not_awaited()
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_activate_episode_moves_existing_item_to_head_and_sets_current() -> None:
    db = _mock_db()
    repo = PodcastRepository(db=db, redis=AsyncMock())
    head = _queue_item(item_id=1, episode_id=10, position=0)
    middle = _queue_item(item_id=2, episode_id=11, position=repo._queue_position_step)
    tail = _queue_item(item_id=3, episode_id=12, position=repo._queue_position_step * 2)
    queue = _queue_with_items([head, middle, tail], current_episode_id=10)

    repo.get_queue_with_items = AsyncMock(side_effect=[queue, queue])
    repo._rewrite_queue_positions = AsyncMock()

    await repo.activate_episode(user_id=1, episode_id=11, max_items=500)

    assert middle.position == -repo._queue_position_step
    assert queue.current_episode_id == 11
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_complete_current_advances_to_next_when_current_not_head() -> None:
    db = _mock_db()
    repo = PodcastRepository(db=db, redis=AsyncMock())
    first = _queue_item(item_id=1, episode_id=10, position=0)
    second = _queue_item(item_id=2, episode_id=11, position=repo._queue_position_step)
    third = _queue_item(
        item_id=3, episode_id=12, position=repo._queue_position_step * 2
    )
    queue = _queue_with_items([first, second, third], current_episode_id=11)

    repo.get_queue_with_items = AsyncMock(side_effect=[queue, queue])
    repo._rewrite_queue_positions = AsyncMock()

    await repo.complete_current(user_id=1)

    db.delete.assert_awaited_once_with(second)
    assert queue.current_episode_id == 12
    assert third.position == -repo._queue_position_step
    db.commit.assert_awaited_once()


@pytest.mark.asyncio
async def test_add_or_move_to_tail_compacts_positions_when_threshold_reached() -> None:
    db = _mock_db()
    repo = PodcastRepository(db=db, redis=AsyncMock())
    queue = _queue_with_items(
        [
            _queue_item(
                item_id=1,
                episode_id=10,
                position=repo._queue_position_compaction_threshold - 1,
            ),
            _queue_item(
                item_id=2,
                episode_id=11,
                position=repo._queue_position_compaction_threshold,
            ),
        ],
        current_episode_id=10,
    )

    repo.get_queue_with_items = AsyncMock(side_effect=[queue, queue])
    repo._rewrite_queue_positions = AsyncMock()

    await repo.add_or_move_to_tail(user_id=1, episode_id=12, max_items=500)

    repo._rewrite_queue_positions.assert_awaited_once()
    db.commit.assert_awaited_once()
