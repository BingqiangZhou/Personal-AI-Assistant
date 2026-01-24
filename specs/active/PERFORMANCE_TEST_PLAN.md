# Performance Test Plan / 性能测试计划

## Document Info / 文档信息

| Field / 字段 | Value / 值 |
|--------------|------------|
| Created / 创建日期 | 2025-01-24 |
| Status / 状态 | Active |
| Version / 版本 | 1.0 |
| Related PRD / 相关需求 | PRD_performance_optimization_20250124 |

---

## 1. Test Objectives / 测试目标

### Primary Objectives / 主要目标

1. **Verify Response Times / 验证响应时间**
   - Podcast list loading: < 500ms
   - Search response: < 300ms
   - User stats: < 200ms
   - Episode list: < 400ms

2. **Measure Cache Effectiveness / 测量缓存有效性**
   - Target cache hit rate: > 70%
   - Cache invalidation correctness
   - Memory usage within limits

3. **Identify Bottlenecks / 识别瓶颈**
   - Slow queries (> 100ms)
   - N+1 query patterns
   - Memory leaks
   - Connection pool exhaustion

4. **Validate Scalability / 验证可扩展性**
   - Concurrent user handling
   - Database connection pool efficiency
   - Redis performance under load

---

## 2. Test Scenarios / 测试场景

### Scenario 1: Podcast List Loading / 播客列表加载

**Endpoint:** `GET /api/v1/podcasts/subscriptions`

**Test Cases:**

| Case / 用例 | Description / 描述 | Expected / 预期 |
|-------------|-------------------|-----------------|
| TC-PL-001 | First load (cache miss) | < 500ms, single DB query |
| TC-PL-002 | Second load (cache hit) | < 50ms, Redis cache hit |
| TC-PL-003 | Large list (100+ subscriptions) | < 800ms, paginated |
| TC-PL-004 | Slow network (3G) | < 2000ms, graceful degradation |

**Validation Points:**
- No N+1 queries (single query for subscriptions + single query for item counts)
- Cache headers set correctly
- Response includes `X-Response-Time` header

---

### Scenario 2: Search Performance / 搜索性能

**Endpoint:** `GET /api/v1/podcasts/search`

**Test Cases:**

| Case / 用例 | Description / 描述 | Expected / 预期 |
|-------------|-------------------|-----------------|
| TC-SR-001 | Empty query | Returns empty, < 100ms |
| TC-SR-002 | Single word search | < 300ms, uses index |
| TC-SR-003 | Multi-word search | < 400ms, optimized |
| TC-SR-004 | No results | < 200ms, early exit |
| TC-SR-005 | Repeated search (cache) | < 50ms, cache hit |

**Validation Points:**
- Batch playback state fetching (not N+1)
- Search result caching (5 min TTL)
- Debouncing on frontend (400ms)

---

### Scenario 3: User Statistics / 用户统计

**Endpoint:** `GET /api/v1/podcasts/stats`

**Test Cases:**

| Case / 用例 | Description / 描述 | Expected / 预期 |
|-------------|-------------------|-----------------|
| TC-ST-001 | First load (new user) | < 200ms, aggregate query |
| TC-ST-002 | Cached load | < 50ms, Redis hit |
| TC-ST-003 | User with 1000+ episodes | < 300ms, still O(1) |
| TC-ST-004 | After subscription change | Cache invalidation works |

**Validation Points:**
- Single aggregate query (no nested loops)
- Cache invalidates on subscription changes
- 30-minute TTL respected

---

### Scenario 4: Episode List Loading / 单集列表加载

**Endpoint:** `GET /api/v1/podcasts/episodes?subscription_id={id}`

**Test Cases:**

| Case / 用例 | Description / 描述 | Expected / 预期 |
|-------------|-------------------|-----------------|
| TC-EL-001 | First page load | < 400ms |
| TC-EL-002 | Cached load | < 50ms |
| TC-EL-003 | Pagination (page 2+) | < 300ms |
| TC-EL-004 | Large subscription (500+ episodes) | < 600ms |

**Validation Points:**
- Batch playback state fetching
- Cache key includes subscription_id + page + size
- 10-minute TTL

---

### Scenario 5: Concurrent Load / 并发负载

**Test Cases:**

| Case / 用例 | Concurrent Users / 并发用户 | Duration / 时长 | Expected / 预期 |
|-------------|----------------------------|-----------------|-----------------|
| TC-CL-001 | 10 users | 1 minute | No errors, avg < 500ms |
| TC-CL-002 | 50 users | 2 minutes | < 5% error rate |
| TC-CL-003 | 100 users | 5 minutes | Graceful degradation |

**Validation Points:**
- Connection pool not exhausted (max 60 connections)
- Redis handles concurrent requests
- No deadlocks or race conditions

---

## 3. Test Tools / 测试工具

### Backend Testing / 后端测试

```python
# File: backend/tests/performance/test_api_performance.py

import pytest
import time
from httpx import AsyncClient

@pytest.mark.performance
async def test_podcast_list_performance(async_client: AsyncClient):
    """Test podcast list loading performance"""
    start = time.time()
    response = await async_client.get("/api/v1/podcasts/subscriptions")
    duration = (time.time() - start) * 1000

    assert response.status_code == 200
    assert duration < 500, f"Response time {duration}ms exceeds 500ms threshold"
    assert "X-Response-Time" in response.headers

@pytest.mark.performance
async def test_search_performance(async_client: AsyncClient):
    """Test search performance"""
    start = time.time()
    response = await async_client.get("/api/v1/podcasts/search?query=test")
    duration = (time.time() - start) * 1000

    assert response.status_code == 200
    assert duration < 300, f"Search took {duration}ms, exceeds 300ms threshold"

@pytest.mark.performance
async def test_cache_effectiveness(async_client: AsyncClient):
    """Test cache hit rate"""
    # First request (cache miss)
    start = time.time()
    await async_client.get("/api/v1/podcasts/subscriptions")
    first_duration = (time.time() - start) * 1000

    # Second request (should be cache hit)
    start = time.time()
    response = await async_client.get("/api/v1/podcasts/subscriptions")
    second_duration = (time.time() - start) * 1000

    # Cached request should be at least 5x faster
    assert second_duration < first_duration / 5, "Cache not working effectively"
```

### Load Testing / 负载测试

```python
# File: backend/tests/performance/test_load.py

import asyncio
import pytest
from httpx import AsyncClient

@pytest.mark.load
async def test_concurrent_users():
    """Test 50 concurrent users"""
    async def make_request(client: AsyncClient):
        response = await client.get("/api/v1/podcasts/subscriptions")
        assert response.status_code == 200
        return response

    async with AsyncClient(base_url="http://localhost:8000") as client:
        tasks = [make_request(client) for _ in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        errors = [r for r in results if isinstance(r, Exception)]
        error_rate = len(errors) / len(results)

        assert error_rate < 0.05, f"Error rate {error_rate:.2%} exceeds 5%"
```

### Frontend Testing / 前端测试

```dart
// File: frontend/test/performance/performance_test.dart

import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';

void main() {
  group('Performance Tests', () {
    testWidgets('Search debounce reduces API calls', (tester) async {
      // TODO: Implement search debounce test
    });

    test('Page state cache validation', () {
      final state = PodcastSubscriptionState(
        subscriptions: [],
        lastRefreshTime: DateTime.now().subtract(Duration(minutes: 3)),
      );

      expect(state.isDataFresh(), true);
    });
  });
}
```

---

## 4. Benchmark Baselines / 基准线

### Performance Targets / 性能目标

| Metric / 指标 | Before / 优化前 | Target / 目标 | Current / 当前 |
|---------------|----------------|--------------|---------------|
| Podcast List | 2-5s | < 500ms | TBD |
| Search | 1-3s | < 300ms | TBD |
| User Stats | 10-30s | < 200ms | TBD |
| Episode List | 1-2s | < 400ms | TBD |
| Cache Hit Rate | 0% | > 70% | TBD |

### Database Query Targets / 数据库查询目标

| Query Type / 查询类型 | Target / 目标 |
|----------------------|--------------|
| Simple SELECT | < 50ms |
| Aggregate query | < 100ms |
| JOIN with batch fetch | < 150ms |
| Full-text search | < 300ms |

---

## 5. Test Execution Plan / 测试执行计划

### Phase 1: Unit Tests / 单元测试 (Week 1)

- [ ] Create performance test framework
- [ ] Implement API endpoint tests
- [ ] Add database query profiling
- [ ] Create frontend widget tests

### Phase 2: Integration Tests / 集成测试 (Week 2)

- [ ] End-to-end flow testing
- [ ] Cache validation tests
- [ ] Concurrent user testing
- [ ] Load testing with locust/k6

### Phase 3: Benchmarking / 基准测试 (Week 3)

- [ ] Establish performance baselines
- [ ] Compare before/after metrics
- [ ] Document improvements
- [ ] Create performance report

---

## 6. Success Criteria / 成功标准

### Must Have / 必须满足

- ✅ All API endpoints meet response time targets
- ✅ Cache hit rate > 70%
- ✅ No N+1 query patterns detected
- ✅ < 5% error rate under 50 concurrent users

### Should Have / 应该满足

- ✅ Response times 50% better than baseline
- ✅ Memory usage < 512MB per worker
- ✅ Database connection pool never exhausted

### Nice to Have / 最好满足

- ✅ Automatic performance regression detection
- ✅ Real-time performance dashboard
- ✅ Performance metrics in CI/CD

---

## 7. Test Environment / 测试环境

### Requirements / 要求

```yaml
# docker-compose.test.yml
services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: test_db
    ports:
      - "5433:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6380:6379"

  backend:
    build: ./backend
    environment:
      DATABASE_URL: postgresql://...
      REDIS_URL: redis://localhost:6380
      ENVIRONMENT: testing
    ports:
      - "8001:8000"
```

---

## 8. Reporting / 报告

### Test Report Template / 测试报告模板

```markdown
# Performance Test Report - [Date]

## Executive Summary
- Overall Status: PASS/FAIL
- Test Duration: X hours
- Total Test Cases: X
- Passed: X, Failed: X

## Results by Scenario
| Scenario | Target | Actual | Status |
|----------|--------|--------|--------|
| Podcast List | < 500ms | XXXms | PASS/FAIL |
| Search | < 300ms | XXXms | PASS/FAIL |
| ...

## Issues Found
1. [Issue description]
   - Severity: High/Medium/Low
   - Recommendation: [Fix]

## Recommendations
[Performance improvement suggestions]
```

---

## 9. Next Steps / 下一步

1. **Immediate / 立即行动**
   - Set up test environment
   - Create test data fixtures
   - Implement first batch of tests

2. **Short-term / 短期**
   - Execute test plan
   - Document results
   - Fix any issues found

3. **Long-term / 长期**
   - Integrate performance tests into CI/CD
   - Set up continuous monitoring
   - Establish performance regression tests
