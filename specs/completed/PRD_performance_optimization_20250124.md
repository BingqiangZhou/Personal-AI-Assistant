# Performance Optimization / 性能优化需求文档

## Basic Information / 基本信息

- **Requirement ID / 需求ID**: REQ-20250124-001
- **Created Date / 创建日期**: 2025-01-24
- **Last Updated / 最后更新**: 2025-01-24
- **Completed Date / 完成日期**: 2025-01-24
- **Owner / 负责人**: Product Manager
- **Status / 状态**: **Completed** ✅
- **Priority / 优先级**: Critical

## Requirement Description / 需求描述

### User Story / 用户故事

**中文**: 作为一名用户，我想要快速浏览播客内容和使用搜索功能，以便高效地发现和收听感兴趣的节目。

**English**: As a user, I want to quickly browse podcast content and use search functionality to efficiently discover and listen to interesting programs.

### Business Value / 业务价值

**中文**:
- 提升用户体验，减少等待时间，增加用户留存率
- 降低服务器负载，减少不必要的数据库查询
- 提高系统并发能力，支持更多用户同时使用
- 改善移动端用户体验，减少流量消耗

**English**:
- Improve user experience, reduce waiting time, increase user retention
- Reduce server load, minimize unnecessary database queries
- Enhance system concurrency, support more simultaneous users
- Improve mobile user experience, reduce data consumption

### Background / 背景信息

**中文**: 经过性能分析，发现以下关键问题：

**后端问题（高优先级）**:
1. **N+1 查询问题** - `podcast/services.py:338` 搜索时对每个 episode 单独查询播放状态
2. **统计计算低效** - `podcast/services.py:569-614` 嵌套循环导致 O(n*m) 次查询
3. **订阅列表重复查询** - `subscription/services.py:52-60` 每个订阅单独 count
4. **缓存使用不足** - Redis 缓存未覆盖常用操作

**前端问题（高优先级）**:
1. **无请求缓存** - `dio_client.dart` 每次导航都重新请求
2. **搜索无防抖** - `podcast_providers.dart:707` 每次按键触发请求
3. **播放更新无节流** - `podcast_providers.dart:384` 拖动进度条触发数十次请求
4. **重复页面加载** - 各页面 initState 总是重新加载

**English**: Performance analysis revealed the following critical issues:

**Backend Issues (High Priority)**:
1. **N+1 Query Problem** - `podcast/services.py:338` Individual playback state queries for each episode during search
2. **Inefficient Statistics Calculation** - `podcast/services.py:569-614` Nested loops causing O(n*m) queries
3. **Subscription List Redundant Queries** - `subscription/services.py:52-60` Individual count for each subscription
4. **Insufficient Cache Usage** - Redis cache not covering common operations

**Frontend Issues (High Priority)**:
1. **No Request Cache** - `dio_client.dart` Re-requests on every navigation
2. **Search Without Debounce** - `podcast_providers.dart:707` Triggers request on every keystroke
3. **Playback Update Without Throttle** - `podcast_providers.dart:384` Tens of requests when dragging progress bar
4. **Repeated Page Loading** - Pages always reload in initState

## Functional Requirements / 功能需求

### Core Features / 核心功能

- **[FR-001]** Backend query optimization (批量查询优化)
- **[FR-002]** Redis caching layer (Redis 缓存层)
- **[FR-003]** Frontend request cache & debounce (前端请求缓存与防抖)
- **[FR-004]** Performance monitoring (性能监控)

### Feature Details / 功能详述

#### Feature 1: Backend Query Optimization / 后端查询优化

**中文**:
- **描述**: 批量获取播放状态，避免 N+1 查询；优化统计计算逻辑
- **输入**: Episode ID 列表、用户 ID
- **处理**: 使用批量查询替代循环查询；使用 SQL 聚合替代应用层计算
- **输出**: 优化的查询结果，减少数据库往返次数

**English**:
- **Description**: Batch fetch playback states to avoid N+1 queries; optimize statistics calculation logic
- **Input**: List of episode IDs, user ID
- **Processing**: Use batch queries instead of loop queries; use SQL aggregation instead of application-level calculation
- **Output**: Optimized query results, reduce database round trips

**具体实现 / Implementation Details**:

1. **Search Episodes / 搜索单集** (Line 320-387):
   - 问题：Line 338 对每个 episode 单独查询 `get_playback_state`
   - 解决方案：使用已实现的 `get_playback_states_batch` (Line 265-267 in `list_episodes`)
   - Expected improvement: 20 episodes × 50ms = 1s → 1 batch query × 100ms = 0.1s (90% faster)

2. **User Stats / 用户统计** (Line 569-614):
   - 问题：嵌套循环查询所有 subscriptions → episodes → playback states
   - 解决方案：使用 SQL JOIN 和 COUNT 聚合一次查询完成
   - Expected improvement: 100 subs × 50 eps × 50ms = 250s → 1 aggregated query × 500ms = 0.5s (99.8% faster)

3. **Subscription List / 订阅列表** (Line 52-60 in subscription/services.py):
   - 问题：每个 subscription 单独 count episodes
   - 解决方案：使用 LEFT JOIN COUNT 一次查询
   - Expected improvement: 20 subs × 50ms = 1s → 1 query × 100ms = 0.1s (90% faster)

#### Feature 2: Redis Caching Layer / Redis 缓存层

**中文**:
- **描述**: 对常用查询结果进行缓存，减少数据库压力
- **输入**: 查询参数（用户ID、订阅ID等）
- **处理**: 检查缓存 → 未命中则查询数据库 → 写入缓存
- **输出**: 缓存数据或数据库查询结果

**English**:
- **Description**: Cache common query results to reduce database pressure
- **Input**: Query parameters (user ID, subscription ID, etc.)
- **Processing**: Check cache → Query database if miss → Write to cache
- **Output**: Cached data or database query results

**缓存策略 / Cache Strategy**:

| Cache Key / 缓存键 | TTL | Invalidated By / 失效条件 |
|-------------------|-----|-------------------------|
| `subscriptions:user:{user_id}:page:{page}` | 5 min | Subscription create/update/delete |
| `episodes:sub:{sub_id}:page:{page}` | 5 min | Episode update, new episodes fetched |
| `playback_states:user:{user_id}:episodes:{ep_ids}` | 10 min | Playback progress update |
| `stats:user:{user_id}` | 15 min | Episode played, subscription added/removed |
| `search:{user_id}:{query_hash}` | 30 min | Episode update, new episodes fetched |

#### Feature 3: Frontend Optimization / 前端优化

**中文**:
- **描述**: 实现请求缓存、搜索防抖、播放进度节流
- **输入**: 用户操作（搜索输入、进度拖动等）
- **处理**: 防抖/节流 + 本地缓存
- **输出**: 减少的不必要网络请求

**English**:
- **Description**: Implement request cache, search debounce, playback progress throttle
- **Input**: User actions (search input, progress dragging, etc.)
- **Processing**: Debounce/throttle + local cache
- **Output**: Reduced unnecessary network requests

**具体实现 / Implementation Details**:

1. **Request Cache / 请求缓存** (dio_client.dart):
   - 使用 `dio_cache_interceptor` 包
   - Cache policy: Cache GET requests for 5 minutes
   - Expected: 70% reduction in navigation requests

2. **Search Debounce / 搜索防抖** (podcast_providers.dart:707):
   - 实现 500ms 防抖
   - 用户停止输入 500ms 后才触发搜索
   - Expected: 90% reduction in search API calls

3. **Playback Progress Throttle / 播放进度节流** (podcast_providers.dart:384):
   - 实现 2 秒节流（拖动时每2秒最多一次请求）
   - + 用户释放进度条时立即更新一次
   - Expected: 95% reduction in progress update requests

4. **Page State Cache / 页面状态缓存**:
   - 使用 Riverpod 的 `keepAlive()` 保存已加载的数据
   - 仅在数据过期时重新请求
   - Expected: 60% reduction in page load requests

#### Feature 4: Performance Monitoring / 性能监控

**中文**:
- **描述**: 添加性能指标收集和监控
- **输入**: 应用程序性能数据
- **处理**: 收集查询时间、缓存命中率、响应时间
- **输出**: 性能报告和告警

**English**:
- **Description**: Add performance metrics collection and monitoring
- **Input**: Application performance data
- **Processing**: Collect query time, cache hit rate, response time
- **Output**: Performance reports and alerts

**监控指标 / Monitoring Metrics**:

- API response time (P50, P95, P99)
- Database query time
- Cache hit rate
- Number of queries per request
- Frontend render time
- Network request count per session

## Non-Functional Requirements / 非功能需求

### Performance Requirements / 性能要求

**中文**:
- **响应时间**:
  - 播客列表加载: < 500ms (当前: 2-5s)
  - 搜索响应: < 300ms (当前: 1-3s)
  - 用户统计加载: < 200ms (当前: 10-30s)
  - 播放进度更新: < 100ms (当前: 频繁卡顿)

- **数据库查询**:
  - 单次 API 请求查询数 < 5 (当前: 50-200)
  - N+1 查询完全消除
  - 缓存命中率 > 70%

- **前端性能**:
  - 首屏加载: < 1s
  - 页面切换: < 200ms
  - 搜索输入延迟: < 100ms (用户感知)
  - 播放进度更新: < 2 秒/次

**English**:
- **Response Time**:
  - Podcast list loading: < 500ms (current: 2-5s)
  - Search response: < 300ms (current: 1-3s)
  - User stats loading: < 200ms (current: 10-30s)
  - Playback progress update: < 100ms (current: frequent lag)

- **Database Queries**:
  - Queries per API request < 5 (current: 50-200)
  - Completely eliminate N+1 queries
  - Cache hit rate > 70%

- **Frontend Performance**:
  - First screen load: < 1s
  - Page navigation: < 200ms
  - Search input lag: < 100ms (user perceived)
  - Playback progress update: < 2s per request

### Security Requirements / 安全要求

**中文**:
- 缓存数据必须隔离（用户不能看到其他用户缓存）
- 敏感数据不缓存（播放令牌等）
- 缓存失效机制保证数据一致性

**English**:
- Cache data must be isolated (users cannot see other users' cache)
- Sensitive data not cached (playback tokens, etc.)
- Cache invalidation mechanism ensures data consistency

### Scalability Requirements / 可扩展性要求

**中文**:
- 支持缓存集群扩展（Redis Cluster）
- 数据库连接池优化
- API 响应时间随用户增长线性增长

**English**:
- Support cache cluster scaling (Redis Cluster)
- Database connection pool optimization
- API response time grows linearly with user growth

## Task Breakdown / 任务分解

### Backend Tasks / 后端任务

- [ ] **[TASK-B-001]** Fix N+1 Query in Search Episodes / 修复搜索单集的 N+1 查询
  - **负责人**: Backend Developer
  - **预估工时**: 2 hours
  - **文件**: `backend/app/domains/podcast/services.py:320-387`
  - **验收标准**:
    - [ ] Replace loop with `get_playback_states_batch`
    - [ ] Unit test: Mock 20 episodes, verify only 1 playback state query
    - [ ] Integration test: Search returns < 500ms
  - **依赖**: None
  - **状态**: Todo

- [ ] **[TASK-B-002]** Optimize User Stats Calculation / 优化用户统计计算
  - **负责人**: Backend Developer
  - **预估工时**: 4 hours
  - **文件**: `backend/app/domains/podcast/services.py:569-614`
  - **验收标准**:
    - [ ] Implement SQL aggregation query (single query)
    - [ ] Unit test: 100 subscriptions, verify query count = 1
    - [ ] Integration test: Stats endpoint returns < 200ms
  - **依赖**: None
  - **状态**: Todo

- [ ] **[TASK-B-003]** Fix Subscription List N+1 Query / 修复订阅列表 N+1 查询
  - **负责人**: Backend Developer
  - **预估工时**: 2 hours
  - **文件**: `backend/app/domains/subscription/services.py:52-60`
  - **验收标准**:
    - [ ] Use LEFT JOIN COUNT aggregation
    - [ ] Unit test: 20 subscriptions, verify query count = 1
    - [ ] Integration test: Subscription list returns < 500ms
  - **依赖**: None
  - **状态**: Todo

- [ ] **[TASK-B-004]** Implement Redis Caching Layer / 实现 Redis 缓存层
  - **负责人**: Backend Developer
  - **预估工时**: 8 hours
  - **文件**: `backend/app/core/redis.py`, new `backend/app/domains/podcast/cache.py`
  - **验收标准**:
    - [ ] Implement cache decorators for common queries
    - [ ] Cache invalidation on create/update/delete
    - [ ] Unit test: Cache hit, cache miss, cache invalidation
    - [ ] Integration test: Cache hit rate > 70%
  - **依赖**: TASK-B-001, TASK-B-002, TASK-B-003
  - **状态**: Todo

- [ ] **[TASK-B-005]** Add Performance Monitoring / 添加性能监控
  - **负责人**: Backend Developer
  - **预估工时**: 6 hours
  - **文件**: New `backend/app/core/metrics.py`
  - **验收标准**:
    - [ ] Collect query time, cache hit rate
    - [ ] Expose metrics endpoint `/api/v1/metrics`
    - [ ] Log slow queries (> 1s)
  - **依赖**: TASK-B-004
  - **状态**: Todo

### Frontend Tasks / 前端任务

- [ ] **[TASK-F-001]** Implement Request Cache / 实现请求缓存
  - **负责人**: Frontend Developer
  - **预估工时**: 4 hours
  - **文件**: `frontend/lib/core/network/dio_client.dart`
  - **验收标准**:
    - [ ] Add `dio_cache_interceptor` dependency
    - [ ] Configure cache policy (5 min TTL)
    - [ ] Widget test: Verify cache hit on second request
  - **依赖**: None
  - **状态**: Todo

- [ ] **[TASK-F-002]** Implement Search Debounce / 实现搜索防抖
  - **负责人**: Frontend Developer
  - **预估工时**: 2 hours
  - **文件**: `frontend/lib/features/podcast/presentation/providers/podcast_providers.dart:707`
  - **验收标准**:
    - [ ] Implement 500ms debounce
    - [ ] Widget test: Verify only 1 request after rapid typing
  - **依赖**: None
  - **状态**: Todo

- [ ] **[TASK-F-003]** Implement Playback Progress Throttle / 实现播放进度节流
  - **负责人**: Frontend Developer
  - **预估工时**: 3 hours
  - **文件**: `frontend/lib/features/podcast/presentation/providers/podcast_providers.dart:384`
  - **验收标准**:
    - [ ] Implement 2s throttle
    - [ ] Immediate update on drag end
    - [ ] Widget test: Verify throttled updates
  - **依赖**: None
  - **状态**: Todo

- [ ] **[TASK-F-004]** Implement Page State Caching / 实现页面状态缓存
  - **负责人**: Frontend Developer
  - **预估工时**: 6 hours
  - **文件**: Multiple provider files
  - **验收标准**:
    - [ ] Use `keepAlive()` for providers
    - [ ] Implement cache invalidation strategy
    - [ ] Widget test: Verify data persistence on navigation
  - **依赖**: None
  - **状态**: Todo

### Test Tasks / 测试任务

- [ ] **[TASK-T-001]** Performance Testing Plan / 性能测试计划
  - **负责人**: Test Engineer
  - **预估工时**: 8 hours
  - **验收标准**:
    - [ ] Design performance test cases (load test, stress test)
    - [ ] Implement automated performance tests (Locust/k6)
    - [ ] Establish performance baseline and benchmarks
    - [ ] Create performance report template
  - **依赖**: TASK-B-001, TASK-B-002, TASK-B-003, TASK-B-004
  - **状态**: Todo

- [ ] **[TASK-T-002]** Execute Performance Tests / 执行性能测试
  - **负责人**: Test Engineer
  - **预估工时**: 4 hours
  - **验收标准**:
    - [ ] Run load tests (simulate 100 concurrent users)
    - [ ] Verify all performance targets met
    - [ ] Generate performance report with before/after comparison
  - **依赖**: TASK-T-001, TASK-F-001, TASK-F-002, TASK-F-003, TASK-F-004
  - **状态**: Todo

## Acceptance Criteria / 验收标准

### Overall Acceptance / 整体验收

**中文**:
- [ ] 所有功能需求已实现
- [ ] 性能指标达标（响应时间、查询数、缓存命中率）
- [ ] 测试覆盖率 > 80%
- [ ] 无回归问题

**English**:
- [ ] All functional requirements implemented
- [ ] Performance metrics met (response time, query count, cache hit rate)
- [ ] Test coverage > 80%
- [ ] No regression issues

### User Acceptance Criteria / 用户验收标准

**中文**:
- [ ] 播客列表在 500ms 内加载完成
- [ ] 搜索在 300ms 内返回结果
- [ ] 搜索输入流畅，无明显延迟
- [ ] 播放进度拖动不卡顿
- [ ] 页面切换快速响应

**English**:
- [ ] Podcast list loads within 500ms
- [ ] Search returns results within 300ms
- [ ] Search input is smooth, no noticeable lag
- [ ] Playback progress dragging is smooth
- [ ] Page navigation is responsive

### Technical Acceptance Criteria / 技术验收标准

**中文**:
- [ ] 单次 API 请求查询数 < 5
- [ ] N+1 查询完全消除
- [ ] Redis 缓存命中率 > 70%
- [ ] 单元测试覆盖率 > 80%
- [ ] 性能测试通过
- [ ] 代码审查通过

**English**:
- [ ] Queries per API request < 5
- [ ] N+1 queries completely eliminated
- [ ] Redis cache hit rate > 70%
- [ ] Unit test coverage > 80%
- [ ] Performance tests passed
- [ ] Code review approved

## Design Constraints / 设计约束

### Technical Constraints / 技术约束

**中文**:
- 必须使用现有的 Redis 基础设施
- 不能修改数据库表结构（除非必要）
- 必须保持 API 兼容性
- Flutter 包版本需与项目兼容

**English**:
- Must use existing Redis infrastructure
- Cannot modify database schema (unless necessary)
- Must maintain API compatibility
- Flutter package versions must be compatible with project

### Business Constraints / 业务约束

**中文**:
- 时间窗口: 2 周内完成
- 不影响现有功能
- 无停机部署（灰度发布）

**English**:
- Time window: Complete within 2 weeks
- No impact on existing functionality
- Zero-downtime deployment (canary release)

## Risk Assessment / 风险评估

### Technical Risks / 技术风险

| 风险项 Risk | 概率 Probability | 影响 Impact | 缓解措施 Mitigation |
|-----------|-----------------|-----------|-------------------|
| **中文**: 缓存一致性问题 <br>**English**: Cache consistency issues | Medium | High | 实现主动失效机制 + 短 TTL<br>Implement active invalidation + short TTL |
| **中文**: 缓存内存溢出 <br>**English**: Cache memory overflow | Low | Medium | 设置缓存上限 + LRU 策略<br>Set cache limit + LRU policy |
| **中文**: 前端缓存导致数据过期 <br>**English**: Frontend cache showing stale data | Medium | Medium | 短 TTL + 主动刷新<br>Short TTL + active refresh |
| **中文**: 性能优化影响功能 <br>**English**: Performance optimization breaks features | Low | High | 完整的回归测试<br>Comprehensive regression testing |

### Business Risks / 业务风险

| 风险项 Risk | 概率 Probability | 影响 Impact | 缓解措施 Mitigation |
|-----------|-----------------|-----------|-------------------|
| **中文**: 开发时间超期 <br>**English**: Development overrun | Medium | Medium | 分阶段发布，优先高影响项<br>Phased release, prioritize high-impact items |
| **中文**: 用户体验下降 <br>**English**: User experience degradation | Low | High | A/B 测试 + 灰度发布<br>A/B testing + canary release |

## Dependencies / 依赖关系

### External Dependencies / 外部依赖

**中文**:
- **Redis**: 缓存存储 - 必须可用，已有基础设施
- **PostgreSQL**: 数据库 - 性能优化依赖查询优化
- **Flutter Packages**: `dio_cache_interceptor`, `flutter_riverpod` - 需要验证兼容性

**English**:
- **Redis**: Cache storage - Must be available, existing infrastructure
- **PostgreSQL**: Database - Performance optimization depends on query optimization
- **Flutter Packages**: `dio_cache_interceptor`, `flutter_riverpod` - Need to verify compatibility

### Internal Dependencies / 内部依赖

**中文**:
- **现有 API 接口**: 需要保持兼容性
- **数据库模型**: 可能需要添加索引
- **前端状态管理**: Riverpod provider 架构

**English**:
- **Existing API interfaces**: Need to maintain compatibility
- **Database models**: May need to add indexes
- **Frontend state management**: Riverpod provider architecture

## Timeline / 时间线

### Milestones / 里程碑

| 里程碑 Milestone | 日期 Date | 说明 Description |
|----------------|----------|----------------|
| **需求确认**<br>Requirement confirmation | 2025-01-24 | Document completed<br>文档完成 |
| **后端优化完成**<br>Backend optimization completed | 2025-01-28 | Tasks B-001 to B-005<br>任务 B-001 到 B-005 |
| **前端优化完成**<br>Frontend optimization completed | 2025-01-30 | Tasks F-001 to F-004<br>任务 F-001 到 F-004 |
| **测试完成**<br>Testing completed | 2025-02-03 | Tasks T-001 to T-002<br>任务 T-001 到 T-002 |
| **灰度发布**<br>Canary release | 2025-02-05 | 10% 用户<br>10% users |
| **全量发布**<br>Full release | 2025-02-07 | 100% 用户<br>100% users |

### Critical Path / 关键路径

**中文**:
1. 需求确认 → 后端优化（TASK-B-001/002/003） → 缓存层（TASK-B-004） → 监控（TASK-B-005）
2. 前端优化（TASK-F-001/002/003/004）可与后端并行
3. 测试（TASK-T-001/002）依赖所有开发任务

**English**:
1. Requirement confirmation → Backend optimization (TASK-B-001/002/003) → Cache layer (TASK-B-004) → Monitoring (TASK-B-005)
2. Frontend optimization (TASK-F-001/002/003/004) can run in parallel with backend
3. Testing (TASK-T-001/002) depends on all development tasks

## Success Metrics / 成功指标

### Quantitative Metrics / 量化指标

**中文**:
- **性能提升**:
  - 播客列表加载时间: 2-5s → < 500ms (80-90% 提升)
  - 搜索响应时间: 1-3s → < 300ms (70-90% 提升)
  - 用户统计时间: 10-30s → < 200ms (98-99% 提升)
  - 单次 API 查询数: 50-200 → < 5 (95%+ 减少)

- **缓存效率**:
  - Redis 缓存命中率: > 70%
  - 前端请求缓存命中率: > 60%

- **用户体验**:
  - 搜索请求减少: 90%
  - 播放进度更新请求减少: 95%
  - 页面导航请求减少: 60%

**English**:
- **Performance Improvement**:
  - Podcast list loading: 2-5s → < 500ms (80-90% improvement)
  - Search response: 1-3s → < 300ms (70-90% improvement)
  - User stats: 10-30s → < 200ms (98-99% improvement)
  - Queries per API: 50-200 → < 5 (95%+ reduction)

- **Cache Efficiency**:
  - Redis cache hit rate: > 70%
  - Frontend request cache hit rate: > 60%

- **User Experience**:
  - Search requests reduced: 90%
  - Playback progress updates reduced: 95%
  - Page navigation requests reduced: 60%

### Qualitative Metrics / 质性指标

**中文**:
- 用户反馈: 搜索和浏览更加流畅
- 用户体验评分提升
- 系统稳定性保持（无新增崩溃）

**English**:
- User feedback: Smoother search and browsing
- User experience score improvement
- System stability maintained (no new crashes)

## Change Log / 变更记录

| 版本 Version | 日期 Date | 变更内容 Changes | 变更人 Author | 审批人 Reviewer |
|-------------|----------|----------------|--------------|----------------|
| 1.0 | 2025-01-24 | Initial creation<br>初始创建 | Product Manager | - |

## Related Documents / 相关文档

- [Performance Analysis Report](#) (性能分析报告)
- [Backend Architecture](../../README.md#backend-architecture) (后端架构)
- [Frontend Architecture](../../README.md#frontend-architecture) (前端架构)
- [API Documentation](https://docs.example.com/api) (API 文档)

## Approval / 审批

### Requirement Review / 需求评审

- [ ] **Product Owner / 产品负责人**: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_
- [ ] **Tech Lead / 技术负责人**: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_
- [ ] **QA Lead / 测试负责人**: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_

### Release Approval / 上线审批

- [ ] **Product Owner / 产品负责人**: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_
- [ ] **Tech Lead / 技术负责人**: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_
- [ ] **DevOps Lead / 运维负责人**: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_

---

**注意 / Note**: This document is the core document for the performance optimization project. Please update it promptly and keep version synchronized.

**本文档是性能优化项目的核心文档，请及时更新并保持版本同步。**
