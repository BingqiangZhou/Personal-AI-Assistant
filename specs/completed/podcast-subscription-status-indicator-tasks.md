# 播客订阅状态指示器 - 任务跟踪文档

**需求文档**: [podcast-subscription-status-indicator.md](./podcast-subscription-status-indicator.md)
**创建时间**: 2026-01-02
**状态**: 进行中
**当前阶段**: 阶段2 - 功能规划与任务分配

---

## 📋 任务总览

| 任务ID | 任务名称 | 负责角色 | 优先级 | 状态 | 依赖关系 |
|--------|---------|---------|--------|------|---------|
| T1 | 后端API增强：搜索结果包含订阅状态 | Backend Developer | P0 | 待开始 | 无 |
| T2 | 前端UI实现：搜索结果卡片显示订阅状态 | Frontend Developer | P0 | 待开始 | T1 |
| T3 | Widget测试：验证订阅状态显示功能 | Test Engineer | P0 | 待开始 | T2 |
| T4 | 端到端测试：完整用户流程验证 | Test Engineer | P1 | 待开始 | T3 |
| T5 | 产品验收：功能完成度验证 | Product Manager | P0 | 待开始 | T4 |

**优先级说明**:
- P0: 必须完成（核心功能）
- P1: 高优先级（质量保证）

---

## 🎯 阶段1：需求分析与定义 ✅

**负责人**: Product Manager
**状态**: 已完成
**完成时间**: 2026-01-02

### 输出成果
- ✅ 需求文档已创建：`specs/active/podcast-subscription-status-indicator.md`
- ✅ 用户故事已定义（3个核心场景）
- ✅ 验收标准已明确（7项标准）
- ✅ 技术要求已分解（前端3项 + 后端3项）

---

## 👥 阶段2：功能规划与任务分配 🔄

**负责人**: Product Manager
**状态**: 进行中
**开始时间**: 2026-01-02

### MVP范围定义

**核心功能（必须包含）**:
1. iTunes搜索API返回订阅状态字段
2. 搜索结果卡片显示订阅状态图标
3. 视觉差异明确（已订阅 vs 未订阅）

**迭代1不包含**:
- 快速订阅/取消订阅按钮（未来迭代）
- 订阅数量统计（未来迭代）
- 批量订阅管理（未来迭代）

### 任务分配详情

---

## ⚙️ 阶段3：开发执行与状态跟踪

### 📌 任务 T1: 后端API增强 - 搜索结果包含订阅状态

**负责人**: Backend Developer ⚙️
**优先级**: P0
**状态**: 待开始
**预估工作量**: 2小时

#### 技术要求
1. **修改iTunes搜索Service** (`backend/app/domains/podcast/services/itunes_search_service.py`)
   - 在`search_podcasts()`方法中增加订阅状态检查逻辑
   - 查询数据库中用户的订阅列表
   - 将订阅状态添加到返回的`PodcastSearchResult`

2. **更新数据模型** (`backend/app/domains/podcast/schemas/podcast.py`)
   - 在`PodcastSearchResult` schema中添加`is_subscribed: bool`字段
   - 添加字段文档说明

3. **数据库查询优化**
   - 使用JOIN查询避免N+1问题
   - 批量检查订阅状态，提高性能

#### 实现建议
```python
# 建议使用 context7 查询 FastAPI 和 SQLAlchemy 文档
# 建议使用 exa 搜索订阅状态检查的最佳实践

# 示例实现思路：
async def search_podcasts(
    self,
    query: str,
    user_id: int,  # 新增参数
    country: str = "us",
    limit: int = 20
) -> List[PodcastSearchResult]:
    # 1. 调用iTunes API获取搜索结果
    results = await self._call_itunes_api(query, country, limit)

    # 2. 批量查询用户订阅状态
    feed_urls = [r.feed_url for r in results]
    subscribed_urls = await self._get_user_subscriptions(user_id, feed_urls)

    # 3. 标记订阅状态
    for result in results:
        result.is_subscribed = result.feed_url in subscribed_urls

    return results
```

#### 验收标准
- [ ] `PodcastSearchResult` schema包含`is_subscribed`字段
- [ ] 搜索API正确返回用户的订阅状态
- [ ] 性能测试：100个搜索结果的订阅状态检查 < 100ms
- [ ] 单元测试覆盖订阅状态检查逻辑
- [ ] API文档自动更新（FastAPI自动生成）

#### 测试命令
```bash
cd docker
docker-compose -f docker-compose.podcast.yml up -d
docker-compose -f docker-compose.podcast.yml exec backend uv run pytest app/domains/podcast/tests/test_itunes_search_service.py -v
```

---

### 📌 任务 T2: 前端UI实现 - 搜索结果卡片显示订阅状态

**负责人**: Frontend Developer 🖥️
**优先级**: P0
**状态**: 待开始
**预估工作量**: 3小时
**依赖**: T1（后端API完成）

#### 技术要求
1. **更新数据模型** (`frontend/lib/features/podcast/data/models/podcast_search_model.dart`)
   - 在`PodcastSearchModel`中添加`isSubscribed`字段
   - 更新JSON序列化代码

2. **修改搜索结果卡片** (`frontend/lib/features/podcast/presentation/widgets/podcast_search_result_card.dart`)
   - 在卡片右上角添加订阅状态图标
   - 已订阅：`Icons.bookmark`（实心书签，主题色）
   - 未订阅：`Icons.bookmark_border`（空心书签，灰色）
   - 添加图标提示文本（Tooltip）

3. **Material 3设计规范**
   - 使用`Theme.of(context).colorScheme.primary`作为已订阅图标颜色
   - 使用`Theme.of(context).colorScheme.outline`作为未订阅图标颜色
   - 图标大小：24x24 dp
   - 位置：卡片右上角，距离边缘12dp

#### 实现建议
```dart
// 建议使用 context7 查询 Material 3 图标文档
// 建议使用 exa 搜索 Flutter 书签图标的最佳实践

// 示例实现思路：
class PodcastSearchResultCard extends StatelessWidget {
  final PodcastSearchModel podcast;

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Stack(
        children: [
          // 现有的卡片内容
          _buildCardContent(),

          // 订阅状态指示器（右上角）
          Positioned(
            top: 12,
            right: 12,
            child: _buildSubscriptionIndicator(context),
          ),
        ],
      ),
    );
  }

  Widget _buildSubscriptionIndicator(BuildContext context) {
    final isSubscribed = podcast.isSubscribed;
    final colorScheme = Theme.of(context).colorScheme;

    return Tooltip(
      message: isSubscribed
        ? AppLocalizations.of(context)!.podcastAlreadySubscribed
        : AppLocalizations.of(context)!.podcastNotSubscribed,
      child: Icon(
        isSubscribed ? Icons.bookmark : Icons.bookmark_border,
        color: isSubscribed
          ? colorScheme.primary
          : colorScheme.outline,
        size: 24,
      ),
    );
  }
}
```

#### 国际化文本
需要在本地化文件中添加：
```json
// en.arb
"podcastAlreadySubscribed": "Already subscribed",
"podcastNotSubscribed": "Not subscribed"

// zh.arb
"podcastAlreadySubscribed": "已订阅",
"podcastNotSubscribed": "未订阅"
```

#### 验收标准
- [ ] 搜索结果卡片右上角显示订阅状态图标
- [ ] 已订阅显示实心书签（主题色）
- [ ] 未订阅显示空心书签（灰色）
- [ ] Tooltip正确显示订阅状态文本
- [ ] 图标大小和位置符合Material 3规范
- [ ] 支持中英文国际化
- [ ] 响应式布局：在不同屏幕尺寸下正确显示

#### 测试命令
```bash
cd frontend
flutter analyze lib/features/podcast/presentation/widgets/podcast_search_result_card.dart
flutter run
```

---

### 📌 任务 T3: Widget测试 - 验证订阅状态显示功能

**负责人**: Test Engineer 🧪
**优先级**: P0
**状态**: 待开始
**预估工作量**: 2小时
**依赖**: T2（前端UI完成）

#### 测试范围
1. **Widget测试** (`frontend/test/widget/podcast/podcast_search_result_card_test.dart`)
   - 测试已订阅播客显示实心书签图标
   - 测试未订阅播客显示空心书签图标
   - 测试图标颜色正确性
   - 测试Tooltip文本正确性
   - 测试国际化支持（中英文切换）

2. **Mock数据准备**
   - 创建已订阅播客的测试数据
   - 创建未订阅播客的测试数据

#### 测试用例设计
```dart
// 建议使用 exa 搜索 Flutter Widget 测试最佳实践

void main() {
  group('PodcastSearchResultCard - Subscription Status Indicator', () {
    testWidgets('显示已订阅图标当播客已被订阅', (WidgetTester tester) async {
      // Given: 已订阅的播客
      final subscribedPodcast = PodcastSearchModel(
        collectionId: 123,
        collectionName: 'Test Podcast',
        isSubscribed: true,
        // ... other fields
      );

      // When: 渲染卡片
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PodcastSearchResultCard(podcast: subscribedPodcast),
          ),
        ),
      );

      // Then: 验证实心书签图标存在
      expect(find.byIcon(Icons.bookmark), findsOneWidget);
      expect(find.byIcon(Icons.bookmark_border), findsNothing);
    });

    testWidgets('显示未订阅图标当播客未被订阅', (WidgetTester tester) async {
      // Given: 未订阅的播客
      final unsubscribedPodcast = PodcastSearchModel(
        collectionId: 456,
        collectionName: 'Another Podcast',
        isSubscribed: false,
        // ... other fields
      );

      // When: 渲染卡片
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PodcastSearchResultCard(podcast: unsubscribedPodcast),
          ),
        ),
      );

      // Then: 验证空心书签图标存在
      expect(find.byIcon(Icons.bookmark_border), findsOneWidget);
      expect(find.byIcon(Icons.bookmark), findsNothing);
    });

    testWidgets('Tooltip显示正确的订阅状态文本', (WidgetTester tester) async {
      // Test implementation
    });

    testWidgets('图标颜色符合Material 3规范', (WidgetTester tester) async {
      // Test implementation
    });

    testWidgets('支持国际化 - 中英文切换', (WidgetTester tester) async {
      // Test implementation
    });
  });
}
```

#### 验收标准
- [ ] 所有测试用例通过（至少5个测试用例）
- [ ] 测试覆盖已订阅和未订阅两种状态
- [ ] 测试覆盖图标类型、颜色、位置
- [ ] 测试覆盖Tooltip文本
- [ ] 测试覆盖国际化支持
- [ ] 测试代码清晰易读，有详细注释

#### 测试命令
```bash
cd frontend
flutter test test/widget/podcast/podcast_search_result_card_test.dart
flutter test --coverage
```

---

### 📌 任务 T4: 端到端测试 - 完整用户流程验证

**负责人**: Test Engineer 🧪
**优先级**: P1
**状态**: 待开始
**预估工作量**: 1.5小时
**依赖**: T3（Widget测试完成）

#### 测试场景
1. **搜索未订阅播客**
   - 用户搜索"tech podcast"
   - 验证搜索结果显示空心书签图标
   - 验证Tooltip显示"未订阅"

2. **搜索已订阅播客**
   - 用户先订阅一个播客
   - 再次搜索该播客
   - 验证搜索结果显示实心书签图标
   - 验证Tooltip显示"已订阅"

3. **混合搜索结果**
   - 搜索结果包含已订阅和未订阅播客
   - 验证每个卡片的订阅状态图标正确

#### 验收标准
- [ ] 完整用户流程可以正常执行
- [ ] 订阅状态在搜索结果中实时反映
- [ ] 性能测试：搜索响应时间 < 2秒
- [ ] 无UI闪烁或布局问题
- [ ] 跨平台测试：Desktop + Web测试通过

#### 测试命令
```bash
cd frontend
flutter run  # 手动测试用户流程
flutter test test/integration/  # 如有集成测试
```

---

### 📌 任务 T5: 产品验收 - 功能完成度验证

**负责人**: Product Manager 📋
**优先级**: P0
**状态**: 待开始
**预估工作量**: 1小时
**依赖**: T4（端到端测试完成）

#### 验收检查清单

**用户故事验证**:
- [ ] 用户故事1：快速识别已订阅播客 ✓
- [ ] 用户故事2：避免重复订阅 ✓
- [ ] 用户故事3：发现新内容 ✓

**验收标准验证**:
- [ ] AC1：搜索结果包含订阅状态信息 ✓
- [ ] AC2：订阅状态实时更新 ✓
- [ ] AC3：视觉差异明确 ✓
- [ ] AC4：性能要求满足 ✓
- [ ] AC5：无重复API调用 ✓
- [ ] AC6：国际化支持 ✓
- [ ] AC7：Material 3设计规范 ✓

**技术要求验证**:
- [ ] 后端API正确返回订阅状态
- [ ] 前端UI符合设计规范
- [ ] 性能指标满足要求
- [ ] 测试覆盖完整

#### 最终决策
- [ ] **通过验收** → 需求状态更新为"已完成"，移动到`specs/completed/`
- [ ] **需要改进** → 制定改进计划，返回阶段2重新分配任务

---

## 📊 进度跟踪

### 整体进度
- **总任务数**: 5
- **已完成**: 0
- **进行中**: 0
- **待开始**: 5
- **完成度**: 0%

### 里程碑
- [ ] **M1**: 后端API开发完成（T1） - 目标：2026-01-02
- [ ] **M2**: 前端UI开发完成（T2） - 目标：2026-01-02
- [ ] **M3**: 测试完成（T3, T4） - 目标：2026-01-02
- [ ] **M4**: 产品验收通过（T5） - 目标：2026-01-02

---

## 🚧 风险与阻塞点

### 潜在风险
1. **性能风险**：批量订阅状态查询可能影响搜索速度
   - **缓解方案**：使用JOIN查询优化，添加数据库索引

2. **兼容性风险**：现有订阅数据可能缺少feed_url字段
   - **缓解方案**：数据迁移脚本，为旧数据填充feed_url

3. **UI冲突风险**：图标位置可能与现有元素重叠
   - **缓解方案**：使用Stack布局，精确控制位置

### 当前阻塞点
- 无

---

## 📝 决策记录

### 2026-01-02
- **决策**: 使用书签图标（`Icons.bookmark`）表示订阅状态
  - **理由**: 用户熟悉，语义明确，Material 3标准图标
  - **替代方案**: 星标（`Icons.star`）- 被拒绝，因为星标通常表示收藏/喜欢

- **决策**: 图标位置在卡片右上角
  - **理由**: 不干扰主要信息（标题、作者），视觉聚焦
  - **替代方案**: 卡片底部 - 被拒绝，因为可能被滚动隐藏

---

## 🔄 更新日志

### 2026-01-02 14:30
- 创建任务跟踪文档
- 定义5个核心任务
- 明确任务优先级和依赖关系
- 编写详细的技术实现建议

---

## 📞 联系与协作

### 任务负责人
- **Backend Developer**: 负责任务T1
- **Frontend Developer**: 负责任务T2
- **Test Engineer**: 负责任务T3, T4
- **Product Manager**: 负责任务T5（验收）

### 沟通渠道
- **进度更新**: 每日在此文档更新任务状态
- **技术问题**: 在具体任务章节下记录
- **阻塞点**: 立即在"风险与阻塞点"章节标记

---

**下一步行动**: Backend Developer开始执行任务T1 ⚙️
