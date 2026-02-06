"""
Performance Tests for API Endpoints

Tests response times, cache effectiveness, and query efficiency.
"""

import asyncio
import os
import time
from typing import Any

import pytest
from httpx import AsyncClient


if os.getenv("RUN_PERFORMANCE_TESTS") != "1":
    pytest.skip(
        "Set RUN_PERFORMANCE_TESTS=1 to run performance benchmark tests.",
        allow_module_level=True,
    )


class PerformanceMetrics:
    """Track performance metrics during tests"""
    def __init__(self):
        self.results: list[dict[str, Any]] = []

    def add_result(self, name: str, duration_ms: float, passed: bool, details: str = ""):
        self.results.append({
            'test': name,
            'duration_ms': duration_ms,
            'passed': passed,
            'details': details
        })

    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 60)
        print("PERFORMANCE TEST SUMMARY")
        print("=" * 60)

        passed = sum(1 for r in self.results if r['passed'])
        total = len(self.results)

        for result in self.results:
            status = "�?PASS" if result['passed'] else "�?FAIL"
            print(f"{status} | {result['test']}: {result['duration_ms']:.2f}ms")
            if result['details']:
                print(f"     Details: {result['details']}")

        print("-" * 60)
        print(f"Total: {passed}/{total} tests passed")
        print("=" * 60)


metrics = PerformanceMetrics()


@pytest.mark.performance
@pytest.mark.asyncio
async def test_podcast_list_first_load_performance(async_client: AsyncClient):
    """Test podcast list first load performance (cache miss)"""
    # Clear cache before test
    # Note: In real test, we'd clear Redis cache here

    start = time.time()
    response = await async_client.get("/api/v1/subscriptions/podcasts")
    duration_ms = (time.time() - start) * 1000

    passed = response.status_code == 200 and duration_ms < 500
    details = f"Status: {response.status_code}" if not passed else ""

    metrics.add_result("Podcast List (First Load)", duration_ms, passed, details)
    assert passed, f"Response time {duration_ms}ms exceeds 500ms threshold"


@pytest.mark.performance
@pytest.mark.asyncio
async def test_podcast_list_cache_performance(async_client: AsyncClient):
    """Test podcast list cache hit performance"""
    # First request to populate cache
    await async_client.get("/api/v1/subscriptions/podcasts")

    # Second request should hit cache
    start = time.time()
    response = await async_client.get("/api/v1/subscriptions/podcasts")
    duration_ms = (time.time() - start) * 1000

    passed = response.status_code == 200 and duration_ms < 100
    details = f"Cached response took {duration_ms}ms"

    metrics.add_result("Podcast List (Cached)", duration_ms, passed, details)
    assert passed, f"Cached response {duration_ms}ms too slow (cache may not be working)"


@pytest.mark.performance
@pytest.mark.asyncio
async def test_search_performance(async_client: AsyncClient):
    """Test search endpoint performance"""
    start = time.time()
    response = await async_client.get("/api/v1/podcasts/search?query=test&search_in=title")
    duration_ms = (time.time() - start) * 1000

    passed = response.status_code == 200 and duration_ms < 300
    metrics.add_result("Search Endpoint", duration_ms, passed)
    assert passed, f"Search took {duration_ms}ms, exceeds 300ms threshold"


@pytest.mark.performance
@pytest.mark.asyncio
async def test_search_cache_performance(async_client: AsyncClient):
    """Test search result caching"""
    query = "performance test"

    # First search
    await async_client.get(f"/api/v1/podcasts/search?query={query}")

    # Second search (should hit cache)
    start = time.time()
    response = await async_client.get(f"/api/v1/podcasts/search?query={query}")
    duration_ms = (time.time() - start) * 1000

    passed = response.status_code == 200 and duration_ms < 50
    metrics.add_result("Search (Cached)", duration_ms, passed)


@pytest.mark.performance
@pytest.mark.asyncio
async def test_user_stats_performance(async_client: AsyncClient):
    """Test user statistics performance"""
    start = time.time()
    response = await async_client.get("/api/v1/podcasts/stats")
    duration_ms = (time.time() - start) * 1000

    passed = response.status_code == 200 and duration_ms < 200
    metrics.add_result("User Stats", duration_ms, passed)
    assert passed, f"Stats took {duration_ms}ms, exceeds 200ms threshold"


@pytest.mark.performance
@pytest.mark.asyncio
async def test_episode_list_performance(async_client: AsyncClient, async_session):
    """Test episode list loading performance"""
    # First get a subscription ID
    response = await async_client.get("/api/v1/subscriptions/podcasts")
    if response.status_code != 200 or not response.json()['subscriptions']:
        pytest.skip("No subscriptions available")

    subscription_id = response.json()['subscriptions'][0]['id']

    start = time.time()
    response = await async_client.get(f"/api/v1/podcasts/episodes?subscription_id={subscription_id}")
    duration_ms = (time.time() - start) * 1000

    passed = response.status_code == 200 and duration_ms < 400
    metrics.add_result("Episode List", duration_ms, passed)
    assert passed, f"Episode list took {duration_ms}ms, exceeds 400ms threshold"


@pytest.mark.load
@pytest.mark.asyncio
async def test_concurrent_users(async_client: AsyncClient):
    """Test performance with 10 concurrent users"""
    async def make_request(client: AsyncClient, user_id: int):
        start = time.time()
        response = await client.get("/api/v1/subscriptions/podcasts")
        duration_ms = (time.time() - start) * 1000
        return user_id, duration_ms, response.status_code

    # Simulate 10 concurrent users
    start = time.time()
    tasks = [make_request(async_client, i) for i in range(10)]
    results = await asyncio.gather(*tasks)
    total_time = (time.time() - start) * 1000

    # Check results
    errors = sum(1 for _, status in [(r[0], r[2]) for r in results] if status != 200)
    avg_duration = sum(r[1] for r in results) / len(results)

    passed = errors == 0 and avg_duration < 500
    details = f"Errors: {errors}, Avg: {avg_duration:.2f}ms"

    metrics.add_result("Concurrent Users (10)", total_time, passed, details)
    assert errors == 0, f"{errors} requests failed out of 10"


@pytest.mark.load
@pytest.mark.asyncio
async def test_cache_hit_rate_measurement(async_client: AsyncClient):
    """Measure cache hit rate over multiple requests"""
    num_requests = 10

    # Warm up cache
    await async_client.get("/api/v1/subscriptions/podcasts")

    cache_hits = 0
    total_time = 0

    for _ in range(num_requests):
        start = time.time()
        response = await async_client.get("/api/v1/subscriptions/podcasts")
        duration_ms = (time.time() - start) * 1000
        total_time += duration_ms

        # Consider it a cache hit if response is fast (< 100ms)
        if duration_ms < 100:
            cache_hits += 1

    hit_rate = (cache_hits / num_requests) * 100
    avg_time = total_time / num_requests

    passed = hit_rate >= 70
    details = f"Hit rate: {hit_rate:.1f}%, Avg time: {avg_time:.2f}ms"

    metrics.add_result("Cache Hit Rate", avg_time, passed, details)
    assert passed, f"Cache hit rate {hit_rate:.1f}% is below 70% threshold"


@pytest.fixture(scope="session", autouse=True)
def print_performance_summary():
    """Print performance test summary at end of session"""
    yield
    metrics.print_summary()


# Performance threshold constants
PERFORMANCE_THRESHOLDS = {
    'podcast_list': 500,  # ms
    'search': 300,
    'user_stats': 200,
    'episode_list': 400,
    'cached_response': 100,
    'cache_hit_rate': 70,  # percent
}
