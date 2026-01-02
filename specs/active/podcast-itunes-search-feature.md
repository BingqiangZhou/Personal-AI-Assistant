# 播客搜索功能 - iTunes Search API 集成

## 基本信息
- **需求ID**: REQ-20250102-001
- **创建日期**: 2025-01-02
- **最后更新**: 2025-01-02
- **负责人**: 产品经理
- **状态**: Active
- **优先级**: High

## 需求描述 / Requirement Description

### 用户故事 / User Story

**中文**:
作为播客听众，我希望在播客订阅页面能够直接搜索和发现播客，而不需要手动输入RSS链接，以便更轻松地找到和订阅我感兴趣的内容。

**English**:
As a podcast listener, I want to be able to search and discover podcasts directly on the subscription page without manually entering RSS links, so that I can more easily find and subscribe to content I'm interested in.

### 业务价值 / Business Value

**中文**:
1. **提升用户体验**: 降低订阅新播客的门槛，从手动输入RSS链接变为搜索点击
2. **增加用户粘性**: 更容易发现新内容，提高用户活跃度和留存率
3. **扩展播客库**: 用户可以发现和订阅更多播客，丰富平台内容
4. **竞争优势**: 提供便捷的搜索功能，提升产品竞争力

**English**:
1. **Enhanced User Experience**: Lower the barrier to subscribing to new podcasts by changing from manual RSS entry to search-and-click
2. **Increased User Engagement**: Easier content discovery leads to higher user activity and retention rates
3. **Expanded Podcast Library**: Users can discover and subscribe to more podcasts, enriching platform content
4. **Competitive Advantage**: Providing convenient search functionality enhances product competitiveness

### 背景信息 / Background Information

**中文**:
- **当前状况**:
  - 用户只能通过手动输入RSS链接订阅播客
  - 没有播客搜索和发现功能
  - 新用户难以找到感兴趣的播客内容
  - 需要用户提前知道播客的RSS链接

- **用户痛点**:
  - 手动输入RSS链接繁琐且容易出错
  - 不知道有哪些播客可以订阅
  - 难以发现新播客
  - 移动端输入长URL体验不佳

- **机会点**:
  - iTunes Search API 提供丰富的播客数据源
  - 可以实现搜索建议和热门推荐
  - 支持中英文搜索，覆盖全球播客内容
  - 可以根据用户位置提供本地化内容

**English**:
- **Current Situation**:
  - Users can only subscribe by manually entering RSS links
  - No podcast search and discovery functionality
  - New users struggle to find interesting podcast content
  - Users need to know the RSS link in advance

- **User Pain Points**:
  - Manual RSS entry is cumbersome and error-prone
  - Don't know what podcasts are available to subscribe
  - Difficult to discover new podcasts
  - Poor experience entering long URLs on mobile devices

- **Opportunities**:
  - iTunes Search API provides rich podcast data source
  - Can implement search suggestions and popular recommendations
  - Supports Chinese and English search, covering global podcast content
  - Can provide localized content based on user location

## 功能需求 / Functional Requirements

### 核心功能 / Core Features

- **中文**:
  - [FR-001] 播客搜索UI界面
  - [FR-002] iTunes Search API 集成
  - [FR-003] 搜索结果显示和订阅
  - [FR-004] 搜索历史和建议
  - [FR-005] 错误处理和用户反馈

**English**:
  - [FR-001] Podcast Search UI Interface
  - [FR-002] iTunes Search API Integration
  - [FR-003] Search Results Display and Subscription
  - [FR-004] Search History and Suggestions
  - [FR-005] Error Handling and User Feedback

### 功能详述 / Feature Details

#### 功能1: 播客搜索UI界面 / Feature 1: Podcast Search UI Interface

**中文**:
- **描述**:
  - 在播客订阅页面 (podcast_list_page) 添加搜索图标按钮
  - 点击后展开为搜索输入框（动画过渡效果）
  - 支持实时搜索（输入时自动触发，带防抖）
  - 显示加载状态和搜索结果数量
  - **国家/地区选择器**（中国/美国）

- **UI组件**:
  - 搜索图标按钮 (IconButton with Icons.search)
  - 搜索输入框 (TextField with clear button)
  - **国家选择器** (SegmentedButton 或 DropdownButton)
  - 搜索结果列表 (ListView with cards)
  - 空状态提示 (EmptyState widget)
  - 加载指示器 (CircularProgressIndicator)

- **国家选择器设计**:
  ```dart
  // Material 3 SegmentedButton
  SegmentedButton<PodcastCountry>(
    segments: [
      ButtonSegment(
        value: PodcastCountry.china,
        label: Text('中国'),
        icon: Icon(Icons.flag),
      ),
      ButtonSegment(
        value: PodcastCountry.usa,
        label: Text('美国'),
        icon: Icon(Icons.flag),
      ),
    ],
    selected: {selectedCountry},
    onSelectionChanged: (Set<PodcastCountry> newSelection) {
      setState(() {
        selectedCountry = newSelection.first;
        // 保存用户选择到本地存储
      });
    },
  )
  ```

- **国家代码映射**:
  ```dart
  enum PodcastCountry {
    china('cn', '中国'),
    usa('us', '美国');

    final String code;
    final String displayName;
    const PodcastCountry(this.code, this.displayName);
  }
  ```

- **默认国家选择逻辑**:
  ```dart
  // 根据用户系统语言自动选择默认国家
  PodcastCountry getDefaultCountry() {
    final locale = PlatformDispatcher.instance.locale;
    if (locale.languageCode == 'zh') {
      return PodcastCountry.china;  // 中文用户默认中国
    }
    return PodcastCountry.usa;      // 其他默认美国
  }
  ```

- **交互要求**:
  - 搜索框展开/收起动画流畅
  - 输入防抖延迟 500ms
  - 支持键盘操作（Enter提交，Esc关闭）
  - 点击搜索结果外部区域关闭搜索
  - **切换国家时自动重新搜索（如果有搜索词）**

- **Material 3设计**:
  - 使用 SearchBar 或 SearchAnchor 组件
  - 使用 SegmentedButton 作为国家选择器
  - 遵循 Material 3 搜索规范
  - 适配桌面和移动端布局
  - 支持暗黑模式

**English**:
- **Description**:
  - Add search icon button on podcast subscription page (podcast_list_page)
  - Expand to search input field on click (with animation transition)
  - Support real-time search (auto-trigger on input with debounce)
  - Display loading state and search result count
  - **Country/Region selector** (China/USA)

- **UI Components**:
  - Search icon button (IconButton with Icons.search)
  - Search input field (TextField with clear button)
  - **Country selector** (SegmentedButton or DropdownButton)
  - Search results list (ListView with cards)
  - Empty state hint (EmptyState widget)
  - Loading indicator (CircularProgressIndicator)

- **Country Selector Design**:
  ```dart
  // Material 3 SegmentedButton
  SegmentedButton<PodcastCountry>(
    segments: [
      ButtonSegment(
        value: PodcastCountry.china,
        label: Text('China'),
        icon: Icon(Icons.flag),
      ),
      ButtonSegment(
        value: PodcastCountry.usa,
        label: Text('USA'),
        icon: Icon(Icons.flag),
      ),
    ],
    selected: {selectedCountry},
    onSelectionChanged: (Set<PodcastCountry> newSelection) {
      setState(() {
        selectedCountry = newSelection.first;
        // Save user selection to local storage
      });
    },
  )
  ```

- **Country Code Mapping**:
  ```dart
  enum PodcastCountry {
    china('cn', 'China'),
    usa('us', 'USA');

    final String code;
    final String displayName;
    const PodcastCountry(this.code, this.displayName);
  }
  ```

- **Default Country Selection Logic**:
  ```dart
  // Auto-select default country based on user's system language
  PodcastCountry getDefaultCountry() {
    final locale = PlatformDispatcher.instance.locale;
    if (locale.languageCode == 'zh') {
      return PodcastCountry.china;  // Chinese users default to China
    }
    return PodcastCountry.usa;      // Others default to USA
  }
  ```

- **Interaction Requirements**:
  - Smooth search box expand/collapse animation
  - Input debounce delay 500ms
  - Support keyboard operations (Enter to submit, Esc to close)
  - Click outside search results to close search
  - **Re-search automatically when country is switched (if there's a search term)**

- **Material 3 Design**:
  - Use SearchBar or SearchAnchor component
  - Use SegmentedButton for country selector
  - Follow Material 3 search guidelines
  - Adapt to desktop and mobile layouts
  - Support dark mode

#### 功能2: iTunes Search API 集成（前端直连）/ Feature 2: iTunes Search API Integration (Frontend Direct Call)

**中文**:
- **描述**:
  - **前端直接调用 iTunes Search API 和 Lookup API**（无需后端代理）
  - Search API: 根据关键词搜索播客
  - Lookup API: 根据 iTunes ID 获取播客详细信息（用于验证和补充数据）
  - 提取 `feedUrl` 字段作为 RSS 订阅链接
  - 订阅时调用现有后端 API

- **API 使用场景**:
  | API | 用途 | 端点 | 示例 |
  |-----|------|------|------|
  | **Search API** | 搜索播客（按关键词） | `/search` | 搜索 "科技" 相关播客 |
  | **Lookup API** | 查询播客详情（按ID） | `/lookup` | 验证 feedUrl 是否有效，获取最新信息 |

- **Search API 参数**:
  ```dart
  // 搜索URL
  https://itunes.apple.com/search?term=${term}&media=podcast&entity=podcast&country=${country}&limit=${limit}

  // 参数说明
  term: 搜索关键词（必需，URL编码）
  media: "podcast"（限定媒体类型）
  entity: "podcast"（限定返回播客）
  country: 国家代码（默认 "cn" 或 "US"）
  limit: 返回数量（1-50，默认25）
  ```

- **Lookup API 参数**:
  ```dart
  // 查询URL
  https://itunes.apple.com/lookup?id=${itunesId}&country=${country}

  // 参数说明
  id: iTunes 播客 ID（必需）
  country: 国家代码（可选）
  ```

- **iTunes API 响应关键字段**:
  ```json
  {
    "resultCount": 25,
    "results": [
      {
        "collectionId": 1535809341,        // iTunes ID（用于 Lookup API）
        "collectionName": "播客名称",        // 播客标题
        "artistName": "作者名称",           // 作者
        "artworkUrl100": "封面URL",         // 100x100封面
        "artworkUrl600": "大封面URL",       // 600x600封面
        "feedUrl": "https://...",          // ⭐ RSS订阅链接（重要！）
        "collectionViewUrl": "iTunes链接",
        "primaryGenreName": "分类",         // 分类
        "trackCount": 100,                 // 单集数量
        "releaseDate": "发布日期"
      }
    ]
  }
  ```

- **技术实现**:
  - 使用 `dio` 包直接调用 iTunes API
  - 实现客户端请求缓存（Hive, TTL=1小时）
  - 实现客户端防抖和节流（500ms）
  - 错误重试机制（最多3次）
  - 响应数据转换和过滤
  - **提取 feedUrl 并存储**

**English**:
- **Description**:
  - **Frontend calls iTunes Search API and Lookup API directly** (no backend proxy needed)
  - Search API: Search podcasts by keywords
  - Lookup API: Get podcast details by iTunes ID (for validation and supplementary data)
  - Extract `feedUrl` field as RSS subscription link
  - Call existing backend API when subscribing

- **API Usage Scenarios**:
  | API | Purpose | Endpoint | Example |
  |-----|---------|----------|---------|
  | **Search API** | Search podcasts (by keyword) | `/search` | Search "technology" podcasts |
  | **Lookup API** | Query podcast details (by ID) | `/lookup` | Validate feedUrl, get latest info |

- **Search API Parameters**:
  ```dart
  // Search URL
  https://itunes.apple.com/search?term=${term}&media=podcast&entity=podcast&country=${country}&limit=${limit}

  // Parameters
  term: Search keyword (required, URL-encoded)
  media: "podcast" (limit media type)
  entity: "podcast" (limit return type)
  country: Country code (default "cn" or "US")
  limit: Number of results (1-50, default 25)
  ```

- **Lookup API Parameters**:
  ```dart
  // Lookup URL
  https://itunes.apple.com/lookup?id=${itunesId}&country=${country}

  // Parameters
  id: iTunes podcast ID (required)
  country: Country code (optional)
  ```

- **iTunes API Response Key Fields**:
  ```json
  {
    "resultCount": 25,
    "results": [
      {
        "collectionId": 1535809341,        // iTunes ID (for Lookup API)
        "collectionName": "Podcast Name",  // Podcast title
        "artistName": "Author Name",       // Author
        "artworkUrl100": "Cover URL",      // 100x100 cover
        "artworkUrl600": "Large Cover",    // 600x600 cover
        "feedUrl": "https://...",          // ⭐ RSS subscription link (Important!)
        "collectionViewUrl": "iTunes link",
        "primaryGenreName": "Category",    // Category
        "trackCount": 100,                 // Episode count
        "releaseDate": "Release date"
      }
    ]
  }
  ```

- **Technical Implementation**:
  - Use `dio` package to call iTunes API directly
  - Implement client-side request caching (Hive, TTL=1 hour)
  - Implement client-side debounce and throttling (500ms)
  - Error retry mechanism (max 3 times)
  - Response data transformation and filtering
  - **Extract feedUrl and store**

#### 功能3: 搜索结果显示和订阅 / Feature 3: Search Results Display and Subscription

**中文**:
- **描述**:
  - 以卡片列表形式展示搜索结果
  - 显示播客封面、标题、作者、简介
  - 支持直接订阅（点击订阅按钮）
  - 显示已订阅状态
  - **从 iTunes API 响应中提取 feedUrl**
  - **调用现有后端订阅 API**

- **搜索结果卡片内容**:
  - 播客封面图片 (artworkUrl100, 100x100)
  - 播客标题 (collectionName)
  - 作者名称 (artistName)
  - 分类标签 (primaryGenreName)
  - 单集数量 (trackCount)
  - 订阅按钮（已订阅显示"已订阅"）

- **完整订阅流程**:
  ```
  1. 用户输入关键词 → iTunes Search API
  2. 显示搜索结果（包含 feedUrl）
  3. 用户点击订阅按钮
  4. 前端提取 feedUrl 和播客信息
  5. 调用现有后端订阅 API
     POST /api/v1/podcasts/subscriptions
     {
       "feed_url": "从 iTunes API 提取的 feedUrl",
       "title": "collectionName",
       "author": "artistName",
       "artwork_url": "artworkUrl100",
       "itunes_id": "collectionId"
     }
  6. 订阅成功后更新按钮状态
  7. 显示成功提示（SnackBar）
  ```

- **数据模型**:
  ```dart
  class PodcastSearchResult {
    final int collectionId;          // iTunes ID
    final String collectionName;     // 播客标题
    final String artistName;         // 作者
    final String artworkUrl100;      // 封面URL
    final String feedUrl;            // ⭐ RSS订阅链接（从 iTunes API 提取）
    final String primaryGenreName;   // 分类
    final int trackCount;            // 单集数量
    final bool isSubscribed;         // 是否已订阅
  }
  ```

**English**:
- **Description**:
  - Display search results as a card list
  - Show podcast cover, title, author, description
  - Support direct subscription (click subscribe button)
  - Display subscription status
  - **Extract feedUrl from iTunes API response**
  - **Call existing backend subscription API**

- **Search Result Card Content**:
  - Podcast cover image (artworkUrl100, 100x100)
  - Podcast title (collectionName)
  - Author name (artistName)
  - Category tag (primaryGenreName)
  - Episode count (trackCount)
  - Subscribe button (show "Subscribed" if already subscribed)

- **Complete Subscription Flow**:
  ```
  1. User enters keyword → iTunes Search API
  2. Display search results (including feedUrl)
  3. User clicks subscribe button
  4. Frontend extracts feedUrl and podcast info
  5. Call existing backend subscription API
     POST /api/v1/podcasts/subscriptions
     {
       "feed_url": "feedUrl extracted from iTunes API",
       "title": "collectionName",
       "author": "artistName",
       "artwork_url": "artworkUrl100",
       "itunes_id": "collectionId"
     }
  6. Update button status after successful subscription
  7. Show success hint (SnackBar)
  ```

- **Data Model**:
  ```dart
  class PodcastSearchResult {
    final int collectionId;          // iTunes ID
    final String collectionName;     // Podcast title
    final String artistName;         // Author
    final String artworkUrl100;      // Cover URL
    final String feedUrl;            // ⭐ RSS subscription link (extracted from iTunes API)
    final String primaryGenreName;   // Category
    final int trackCount;            // Episode count
    final bool isSubscribed;         // Subscription status
  }
  ```

#### 功能4: 搜索历史和建议 / Feature 4: Search History and Suggestions

**中文**:
- **描述**:
  - 保存用户最近搜索历史（本地存储）
  - 显示搜索历史作为快速搜索选项
  - 提供清除历史功能
  - （可选）显示热门播客推荐

- **搜索历史功能**:
  - 最多保存10条搜索历史
  - 使用 Hive 本地存储
  - 显示在搜索框下方
  - 点击历史项快速搜索
  - 提供清除历史按钮

- **实现优先级**: Phase 2（可选功能）

**English**:
- **Description**:
  - Save user's recent search history (local storage)
  - Display search history as quick search options
  - Provide clear history functionality
  - (Optional) Display popular podcast recommendations

- **Search History Features**:
  - Save up to 10 search history items
  - Use Hive local storage
  - Display below search box
  - Click history item for quick search
  - Provide clear history button

- **Implementation Priority**: Phase 2 (Optional feature)

#### 功能5: 错误处理和用户反馈 / Feature 5: Error Handling and User Feedback

**中文**:
- **网络错误**:
  - 显示友好的错误提示
  - 提供重试按钮
  - 离线状态检测

- **API限流处理**:
  - 检测 iTunes API 限流（429状态码）
  - 显示"搜索过于频繁，请稍后再试"
  - 实现客户端限流提示

- **无结果提示**:
  - 显示"未找到相关播客"
  - 提供搜索建议（尝试其他关键词）
  - 显示空状态插图

- **订阅失败处理**:
  - RSS链接无效
  - 网络错误
  - 服务器错误
  - 提供重试机制

**English**:
- **Network Errors**:
  - Display friendly error messages
  - Provide retry button
  - Offline status detection

- **API Rate Limiting**:
  - Detect iTunes API rate limiting (429 status code)
  - Show "Searching too frequently, please try again later"
  - Implement client-side rate limiting hint

- **No Results Hint**:
  - Display "No related podcasts found"
  - Provide search suggestions (try other keywords)
  - Display empty state illustration

- **Subscription Failure Handling**:
  - Invalid RSS link
  - Network error
  - Server error
  - Provide retry mechanism

## 非功能需求 / Non-Functional Requirements

### 性能要求 / Performance Requirements

**中文**:
- **搜索响应时间**: < 2秒（首次搜索，无缓存）
- **缓存命中响应**: < 500ms
- **UI动画流畅度**: 60fps
- **搜索结果加载**: 支持分页或懒加载（如果结果>25条）

**English**:
- **Search Response Time**: < 2s (first search, no cache)
- **Cache Hit Response**: < 500ms
- **UI Animation Smoothness**: 60fps
- **Search Results Loading**: Support pagination or lazy loading (if results > 25)

### 安全要求 / Security Requirements

**中文**:
- **输入验证**: 验证和清理搜索关键词，防止注入攻击
- **API密钥管理**: iTunes Search API 不需要密钥（公开API）
- **用户隐私**: 不记录用户搜索历史到服务器（仅本地存储）
- **限流保护**: 防止API滥用

**English**:
- **Input Validation**: Validate and sanitize search keywords to prevent injection attacks
- **API Key Management**: iTunes Search API does not require key (public API)
- **User Privacy**: Do not log user search history to server (local storage only)
- **Rate Limiting**: Prevent API abuse

### 可用性要求 / Usability Requirements

**中文**:
- **系统可用性**: 99.5%（依赖 iTunes API 可用性）
- **降级方案**: iTunes API 不可用时显示提示信息
- **错误恢复**: 网络恢复后自动重试
- **多语言支持**: 支持中英文界面

**English**:
- **System Availability**: 99.5% (depends on iTunes API availability)
- **Fallback Mechanism**: Show prompt when iTunes API is unavailable
- **Error Recovery**: Auto-retry after network recovery
- **Multi-language Support**: Support Chinese and English interface

### 兼容性要求 / Compatibility Requirements

**中文**:
- **平台支持**:
  - Desktop (Windows, macOS, Linux)
  - Web (Chrome, Firefox, Safari, Edge)
  - Mobile (iOS, Android)
- **Docker环境**: 后端服务必须在 Docker 环境中运行
- **API版本**: 兼容现有 /api/v1/podcasts 端点

**English**:
- **Platform Support**:
  - Desktop (Windows, macOS, Linux)
  - Web (Chrome, Firefox, Safari, Edge)
  - Mobile (iOS, Android)
- **Docker Environment**: Backend services must run in Docker environment
- **API Version**: Compatible with existing /api/v1/podcasts endpoints

## API 接口设计 / API Interface Design

### 前端 API 调用 / Frontend API Call

**中文**:

#### 1. iTunes Search API（搜索播客）

```dart
// 前端直接调用 iTunes Search API
class iTunesSearchService {
  static const String _searchBaseUrl = 'https://itunes.apple.com/search';
  static const String _lookupBaseUrl = 'https://itunes.apple.com/lookup';

  // 搜索播客
  Future<List<PodcastSearchResult>> searchPodcasts({
    required String term,
    String country = 'cn',
    int limit = 25,
  }) async {
    final response = await dio.get(
      _searchBaseUrl,
      queryParameters: {
        'term': term,           // 搜索关键词（URL编码）
        'media': 'podcast',     // 限定媒体类型
        'entity': 'podcast',    // 限定返回播客
        'country': country,     // 国家代码
        'limit': limit,         // 返回数量
      },
    );

    // 解析响应
    final data = jsonDecode(response.data);
    final results = (data['results'] as List).map((item) {
      return PodcastSearchResult(
        collectionId: item['collectionId'],
        collectionName: item['collectionName'],
        artistName: item['artistName'],
        artworkUrl100: item['artworkUrl100'],
        feedUrl: item['feedUrl'],  // ⭐ 提取 RSS 订阅链接
        primaryGenreName: item['primaryGenreName'],
        trackCount: item['trackCount'],
      );
    }).toList();

    return results;
  }

  // 查询播客详情（可选，用于验证或获取更多信息）
  Future<PodcastSearchResult?> lookupPodcast({
    required int itunesId,
    String country = 'cn',
  }) async {
    final response = await dio.get(
      _lookupBaseUrl,
      queryParameters: {
        'id': itunesId,
        'country': country,
      },
    );

    // 解析响应...
  }
}
```

#### 2. 现有后端订阅 API（订阅播客）

```dart
// 订阅播客 - 使用现有 API
// POST /api/v1/podcasts/subscriptions

Future<void> subscribeToPodcast(PodcastSearchResult podcast) async {
  final response = await dio.post(
    '/api/v1/podcasts/subscriptions',
    data: {
      'feed_url': podcast.feedUrl,        // ⭐ 从 iTunes API 提取的 RSS 链接
      'title': podcast.collectionName,     // 播客标题
      'author': podcast.artistName,        // 作者
      'artwork_url': podcast.artworkUrl100, // 封面 URL
      'itunes_id': podcast.collectionId,   // iTunes ID
    },
  );

  // 处理响应...
}
```

#### 3. API 调用示例

```dart
// 完整使用示例
class PodcastSearchController {
  final iTunesSearchService _searchService = iTunesSearchService();

  // 1. 搜索播客
  Future<void> search(String keyword) async {
    final results = await _searchService.searchPodcasts(
      term: keyword,
      country: 'cn',
      limit: 25,
    );

    // 显示搜索结果...
  }

  // 2. 订阅播客
  Future<void> subscribe(PodcastSearchResult podcast) async {
    try {
      await subscribeToPodcast(podcast);
      // 显示成功提示
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('订阅成功')),
      );
    } catch (e) {
      // 显示错误提示
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('订阅失败: $e')),
      );
    }
  }
}
```

**English**:

#### 1. iTunes Search API (Search Podcasts)

```dart
// Frontend calls iTunes Search API directly
class iTunesSearchService {
  static const String _searchBaseUrl = 'https://itunes.apple.com/search';
  static const String _lookupBaseUrl = 'https://itunes.apple.com/lookup';

  // Search podcasts
  Future<List<PodcastSearchResult>> searchPodcasts({
    required String term,
    String country = 'cn',
    int limit = 25,
  }) async {
    final response = await dio.get(
      _searchBaseUrl,
      queryParameters: {
        'term': term,           // Search keyword (URL-encoded)
        'media': 'podcast',     // Limit media type
        'entity': 'podcast',    // Limit return type
        'country': country,     // Country code
        'limit': limit,         // Number of results
      },
    );

    // Parse response
    final data = jsonDecode(response.data);
    final results = (data['results'] as List).map((item) {
      return PodcastSearchResult(
        collectionId: item['collectionId'],
        collectionName: item['collectionName'],
        artistName: item['artistName'],
        artworkUrl100: item['artworkUrl100'],
        feedUrl: item['feedUrl'],  // ⭐ Extract RSS subscription link
        primaryGenreName: item['primaryGenreName'],
        trackCount: item['trackCount'],
      );
    }).toList();

    return results;
  }

  // Lookup podcast details (optional, for validation or more info)
  Future<PodcastSearchResult?> lookupPodcast({
    required int itunesId,
    String country = 'cn',
  }) async {
    final response = await dio.get(
      _lookupBaseUrl,
      queryParameters: {
        'id': itunesId,
        'country': country,
      },
    );

    // Parse response...
  }
}
```

#### 2. Existing Backend Subscription API (Subscribe to Podcast)

```dart
// Subscribe to podcast - using existing API
// POST /api/v1/podcasts/subscriptions

Future<void> subscribeToPodcast(PodcastSearchResult podcast) async {
  final response = await dio.post(
    '/api/v1/podcasts/subscriptions',
    data: {
      'feed_url': podcast.feedUrl,        // ⭐ RSS link extracted from iTunes API
      'title': podcast.collectionName,     // Podcast title
      'author': podcast.artistName,        // Author
      'artwork_url': podcast.artworkUrl100, // Cover URL
      'itunes_id': podcast.collectionId,   // iTunes ID
    },
  );

  // Handle response...
}
```

#### 3. API Usage Example

```dart
// Complete usage example
class PodcastSearchController {
  final iTunesSearchService _searchService = iTunesSearchService();

  // 1. Search podcasts
  Future<void> search(String keyword) async {
    final results = await _searchService.searchPodcasts(
      term: keyword,
      country: 'cn',
      limit: 25,
    );

    // Display search results...
  }

  // 2. Subscribe to podcast
  Future<void> subscribe(PodcastSearchResult podcast) async {
    try {
      await subscribeToPodcast(podcast);
      // Show success message
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Subscription successful')),
      );
    } catch (e) {
      // Show error message
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Subscription failed: $e')),
      );
    }
  }
}
```

## UI/UX 设计要求 / UI/UX Design Requirements

### Material 3 设计规范 / Material 3 Design Guidelines

**中文**:
1. **搜索组件**:
   - 使用 `SearchBar` 或 `SearchAnchor` 组件
   - 遵循 Material 3 搜索交互模式
   - 支持全屏搜索模式（移动端）

2. **搜索结果卡片**:
   - 使用 `Card` 组件
   - 圆角: 12px
   - 间距: 8px vertical padding, 16px horizontal padding
   -  elevation: 1 (resting), 4 (pressed)

3. **颜色方案**:
   - 使用主题色彩系统
   - 订阅按钮使用 FilledButton（已订阅使用 OutlinedButton）
   - 错误状态使用 errorContainer

4. **响应式设计**:
   - Desktop: 单列布局，最大宽度 800px
   - Tablet: 2列网格布局
   - Mobile: 单列布局，全屏搜索

5. **无障碍访问**:
   - 所有交互元素有 semantic label
   - 支持键盘导航
   - 适当的对比度

**English**:
1. **Search Component**:
   - Use `SearchBar` or `SearchAnchor` component
   - Follow Material 3 search interaction patterns
   - Support full-screen search mode (mobile)

2. **Search Result Card**:
   - Use `Card` component
   - Border radius: 12px
   - Padding: 8px vertical, 16px horizontal
   - Elevation: 1 (resting), 4 (pressed)

3. **Color Scheme**:
   - Use theme color system
   - Subscribe button uses FilledButton (subscribed uses OutlinedButton)
   - Error state uses errorContainer

4. **Responsive Design**:
   - Desktop: Single column layout, max width 800px
   - Tablet: 2-column grid layout
   - Mobile: Single column layout, full-screen search

5. **Accessibility**:
   - All interactive elements have semantic labels
   - Support keyboard navigation
   - Appropriate contrast ratios

### 页面布局 / Page Layout

**中文**:
```
PodcastListPage
├── AppBar (标题 + 搜索按钮 + 添加按钮)
├── SearchPanel (展开状态)
│   ├── CountrySelector (国家选择器 - 中国/美国) ⭐ 新增
│   ├── SearchBar (搜索输入框)
│   ├── Recent Searches (可选)
│   └── Search Results (ListView)
│       └── PodcastCard × N
│           ├── Cover Image
│           ├── Title & Author
│           ├── Genre Tag
│           └── Subscribe Button
└── SubscriptionList (原有列表)
```

**国家选择器位置**:
```
┌─────────────────────────────────────────┐
│  🔍 Search Podcast                      │
├─────────────────────────────────────────┤
│  [ 中国 🇨🇳 ] [ 美国 🇺🇸 ]  ← SegmentedButton │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────┐   │
│  │ 🔍 搜索播客...               │   │
│  └─────────────────────────────────┘   │
├─────────────────────────────────────────┤
│  搜索结果...                            │
└─────────────────────────────────────────┘
```

**English**:
```
PodcastListPage
├── AppBar (Title + Search Button + Add Button)
├── SearchPanel (Expanded State)
│   ├── CountrySelector (Country Selector - China/USA) ⭐ New
│   ├── SearchBar (Search input field)
│   ├── Recent Searches (Optional)
│   └── Search Results (ListView)
│       └── PodcastCard × N
│           ├── Cover Image
│           ├── Title & Author
│           ├── Genre Tag
│           └── Subscribe Button
└── SubscriptionList (Original List)
```

**Country Selector Position**:
```
┌─────────────────────────────────────────┐
│  🔍 Search Podcast                      │
├─────────────────────────────────────────┤
│  [ China 🇨🇳 ] [ USA 🇺🇸 ]  ← SegmentedButton │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────┐   │
│  │ 🔍 Search podcasts...          │   │
│  └─────────────────────────────────┘   │
├─────────────────────────────────────────┤
│  Search results...                      │
└─────────────────────────────────────────┘
```

## 任务分解 / Task Breakdown

### Frontend任务 / Frontend Tasks

- [ ] [TASK-F-001] 创建 iTunes Search Service
  - **负责人**: Frontend Developer
  - **预估工时**: 3小时
  - **验收标准**:
    - [ ] iTunesSearchService 类实现
    - [ ] Search API 和 Lookup API 调用
    - [ ] 支持国家参数（cn, us）
    - [ ] 实现客户端缓存（Hive, TTL=1小时）
    - [ ] 实现防抖（500ms）
    - [ ] 错误重试机制
    - [ ] 单元测试
  - **依赖**: 无
  - **状态**: Todo

- [ ] [TASK-F-002] 创建国家选择器组件 ⭐ 新增
  - **负责人**: Frontend Developer
  - **预估工时**: 2小时
  - **验收标准**:
    - [ ] CountrySelector widget 实现
    - [ ] 使用 Material 3 SegmentedButton
    - [ ] 支持中国/美国切换
    - [ ] 根据系统语言自动选择默认国家
    - [ ] 保存用户选择到本地存储
    - [ ] 切换国家时触发重新搜索
    - [ ] Widget 测试覆盖
  - **依赖**: 无
  - **状态**: Todo

- [ ] [TASK-F-003] 创建搜索UI组件
  - **负责人**: Frontend Developer
  - **预估工时**: 6小时
  - **验收标准**:
    - [ ] SearchPanel widget 实现
    - [ ] SearchBar/SearchAnchor 集成
    - [ ] 集成 CountrySelector
    - [ ] 展开/收起动画
    - [ ] Material 3 设计规范
    - [ ] 响应式布局
    - [ ] 暗黑模式支持
    - [ ] Widget 测试覆盖
  - **依赖**: TASK-F-002
  - **状态**: Todo

- [ ] [TASK-F-004] 实现搜索结果列表
  - **负责人**: Frontend Developer
  - **预估工时**: 5小时
  - **验收标准**:
    - [ ] PodcastSearchCard widget
    - [ ] ListView 布局
    - [ ] 图片加载和缓存
    - [ ] 加载状态显示
    - [ ] 空状态显示
    - [ ] Widget 测试覆盖
  - **依赖**: TASK-F-003
  - **状态**: Todo

- [ ] [TASK-F-005] 实现搜索状态管理
  - **负责人**: Frontend Developer
  - **预估工时**: 3小时
  - **验收标准**:
    - [ ] podcastSearchProvider
    - [ ] 搜索状态（loading, loaded, error）
    - [ ] 国家选择状态管理
    - [ ] 防抖实现（500ms）
    - [ ] 单元测试
  - **依赖**: TASK-F-001
  - **状态**: Todo

- [ ] [TASK-F-006] 集成搜索到播客列表页
  - **负责人**: Frontend Developer
  - **预估工时**: 4小时
  - **验收标准**:
    - [ ] 搜索按钮添加到 AppBar
    - [ ] SearchPanel 集成
    - [ ] 订阅按钮调用现有API
    - [ ] 状态更新和提示
    - [ ] 双语文本支持
    - [ ] Widget 测试覆盖
  - **依赖**: TASK-F-003, TASK-F-004, TASK-F-005
  - **状态**: Todo

- [ ] [TASK-F-007] 添加搜索历史功能（Phase 2）
  - **负责人**: Frontend Developer
  - **预估工时**: 3小时
  - **验收标准**:
    - [ ] 本地存储集成（Hive）
    - [ ] 搜索历史UI
    - [ ] 清除历史功能
    - [ ] 单元测试
  - **依赖**: TASK-F-006
  - **状态**: Todo

### 测试任务 / Testing Tasks

- [ ] [TASK-T-001] 前端Widget测试
  - **负责人**: Test Engineer
  - **预估工时**: 5小时
  - **验收标准**:
    - [ ] SearchPanel widget 测试
    - [ ] PodcastSearchCard widget 测试
    - [ ] 搜索provider测试
    - [ ] 模拟各种数据状态
    - [ ] 测试覆盖率 > 80%
  - **依赖**: TASK-F-002, TASK-F-003, TASK-F-004
  - **状态**: Todo

- [ ] [TASK-T-002] 集成测试
  - **负责人**: Test Engineer
  - **预估工时**: 3小时
  - **验收标准**:
    - [ ] 端到端搜索流程测试
    - [ ] 订阅流程测试
    - [ ] 错误场景测试
    - [ ] 双语支持测试
  - **依赖**: TASK-F-005
  - **状态**: Todo

- [ ] [TASK-T-003] 手动测试和UI验证
  - **负责人**: Test Engineer
  - **预估工时**: 3小时
  - **验收标准**:
    - [ ] 跨平台UI测试（Desktop, Web, Mobile）
    - [ ] Material 3 设计验证
    - [ ] 暗黑模式测试
    - [ ] 无障碍访问测试
    - [ ] 性能验证
  - [ ] iTunes API 调用验证
  - **依赖**: 所有前端任务
  - **状态**: Todo

## 验收标准 / Acceptance Criteria

### 整体验收 / Overall Acceptance

**中文**:
- [ ] 所有功能需求已实现
- [ ] 通过所有测试用例
- [ ] 性能指标达标
- [ ] 代码质量符合项目标准
- [ ] Docker环境验证通过
- [ ] 用户验收测试通过

**English**:
- [ ] All functional requirements implemented
- [ ] All test cases passed
- [ ] Performance metrics met
- [ ] Code quality meets project standards
- [ ] Docker environment verification passed
- [ ] User acceptance testing passed

### 用户验收标准 / User Acceptance Criteria

**中文**:
- [ ] 用户可以在播客列表页找到搜索按钮
- [ ] 点击搜索按钮后展开搜索框
- [ ] 输入关键词后显示搜索结果
- [ ] 搜索结果显示播客封面、标题、作者信息
- [ ] 点击订阅按钮可以成功订阅播客
- [ ] 已订阅的播客显示正确状态
- [ ] 搜索响应时间小于2秒
- [ ] 错误提示清晰友好
- [ ] 支持中英文搜索

**English**:
- [ ] User can find search button on podcast list page
- [ ] Search box expands after clicking search button
- [ ] Search results display after entering keyword
- [ ] Search results show podcast cover, title, author info
- [ ] Clicking subscribe button successfully subscribes to podcast
- [ ] Subscribed podcasts show correct status
- [ ] Search response time < 2 seconds
- [ ] Error messages are clear and friendly
- [ ] Support Chinese and English search

### 技术验收标准 / Technical Acceptance Criteria

**中文**:
- [ ] 前端代码通过 `flutter analyze` 和 `flutter test`
- [ ] 单元测试覆盖率 > 80%
- [ ] Widget测试覆盖所有新组件
- [ ] 无内存泄漏
- [ ] 遵循 Clean Architecture
- [ ] 代码审查通过
- [ ] iTunes API 调用正常工作
- [ ] 客户端缓存功能正常
- [ ] 订阅API集成正确

**English**:
- [ ] Frontend code passes `flutter analyze` and `flutter test`
- [ ] Unit test coverage > 80%
- [ ] Widget tests cover all new components
- [ ] No memory leaks
- [ ] Follow Clean Architecture
- [ ] Code review passed
- [ ] iTunes API calls work correctly
- [ ] Client-side caching works properly
- [ ] Subscription API integration correct

### 双语验证标准 / Bilingual Validation Criteria

**中文**:
- [ ] 搜索界面支持中英文切换
- [ ] 错误消息提供双语版本
- [ ] 搜索关键词支持中文和英文
- [ ] API返回多语言播客数据
- [ ] 测试中英文搜索功能均正常

**English**:
- [ ] Search interface supports Chinese/English switching
- [ ] Error messages provided in bilingual format
- [ ] Search keywords support Chinese and English
- [ ] API returns multilingual podcast data
- [ ] Both Chinese and English search functions tested and working

## 设计约束 / Design Constraints

### 技术约束 / Technical Constraints

**中文**:
- 前端必须使用 Flutter + Riverpod
- 遵循项目 Clean Architecture（Frontend）
- 使用 Material 3 设计系统
- **前端直接调用 iTunes Search API**（公开API，无需密钥，无需后端代理）
- 使用 Hive 客户端缓存（已有基础设施）
- 订阅时使用现有后端 API

**English**:
- Frontend must use Flutter + Riverpod
- Follow project Clean Architecture (Frontend)
- Use Material 3 design system
- **Frontend calls iTunes Search API directly** (public API, no key required, no backend proxy)
- Use Hive client-side caching (existing infrastructure)
- Use existing backend API when subscribing

### 业务约束 / Business Constraints

**中文**:
- iTunes API 请求限制约20次/分钟（需要实现客户端缓存和防抖）
- 不能修改现有订阅功能
- 必须保持向后兼容
- 搜索结果可能因地区而异（country参数）
- iTunes API 数据质量不完全可控
- 前端直接调用外部API，需要考虑CORS和网络稳定性

**English**:
- iTunes API request limit ~20 requests/minute (need to implement client-side caching and debounce)
- Cannot modify existing subscription functionality
- Must maintain backward compatibility
- Search results may vary by region (country parameter)
- iTunes API data quality not fully controllable
- Frontend calls external API directly, need to consider CORS and network stability

### 环境约束 / Environmental Constraints

**中文**:
- 需要网络连接访问 iTunes API
- iTunes API 可能存在跨域限制（需要验证）
- 移动端网络环境可能不稳定
- 不同平台（Desktop, Web, Mobile）网络请求行为可能不同

**English**:
- Network connection required to access iTunes API
- iTunes API may have CORS restrictions (need to verify)
- Mobile network environment may be unstable
- Network request behavior may vary across platforms (Desktop, Web, Mobile)

## 风险评估 / Risk Assessment

### 技术风险 / Technical Risks

| 风险项 Risk | 概率 Probability | 影响 Impact | 缓解措施 Mitigation |
|-------------|------------------|-------------|-------------------|
| CORS 跨域限制 / CORS Restrictions | 中 Medium | 高 High | iTunes API 支持 CORS，验证并测试跨域请求 / iTunes API supports CORS, verify and test cross-origin requests |
| iTunes API 限流 / API Rate Limiting | 中 Medium | 中 Medium | 实现Hive客户端缓存，减少实际API调用 / Implement Hive client-side caching to reduce actual API calls |
| iTunes API 不可用 / API Unavailability | 低 Low | 高 High | 实现降级方案，显示友好提示 / Implement fallback mechanism with friendly prompts |
| 缓存失效导致性能问题 / Cache Invalidation | 低 Low | 低 Low | 设置合理的TTL（1小时），监控缓存命中率 / Set reasonable TTL (1 hour), monitor cache hit rate |
| 移动端网络不稳定 / Unstable Mobile Network | 高 High | 中 Medium | 实现重试机制，显示离线提示 / Implement retry mechanism, show offline hints |
| RSS链接无效 / Invalid RSS Links | 中 Medium | 中 Medium | 订阅前验证RSS，提供错误提示 / Validate RSS before subscription, provide error hints |
| Web平台跨域问题 / Web Platform CORS | 中 Medium | 中 Medium | 测试Web平台跨域行为，必要时使用代理 / Test Web platform CORS behavior, use proxy if necessary |

### 业务风险 / Business Risks

| 风险项 Risk | 概率 Probability | 影响 Impact | 缓解措施 Mitigation |
|-------------|------------------|-------------|-------------------|
| 用户搜索不到播客 / Users Can't Find Podcasts | 中 Medium | 中 Medium | 提供搜索建议和热门推荐 / Provide search suggestions and popular recommendations |
| iTunes API 数据质量 / API Data Quality | 中 Medium | 低 Low | 过滤无效结果，允许用户手动订阅 / Filter invalid results, allow manual subscription |
| 用户不习惯搜索功能 / Users Not Used to Search | 低 Low | 低 Low | 保留原有订阅方式，提供使用引导 / Keep existing subscription method, provide usage guide |

## 依赖关系 / Dependencies

### 外部依赖 / External Dependencies

**中文**:
- **iTunes Search API**: 核心依赖，提供播客搜索数据
  - 状态: 公开API，稳定
  - SLA: 无官方SLA，但可靠性高
  - 限制: 约20次/分钟
  - CORS: 支持跨域请求

- **Hive**: 客户端缓存存储
  - 用途: 缓存搜索结果，减少API调用
  - 可用性: 已有基础设施

**English**:
- **iTunes Search API**: Core dependency providing podcast search data
  - Status: Public API, stable
  - SLA: No official SLA, but highly reliable
  - Limit: ~20 requests/minute
  - CORS: Supports cross-origin requests

- **Hive**: Client-side cache storage
  - Purpose: Cache search results, reduce API calls
  - Availability: Existing infrastructure

### 内部依赖 / Internal Dependencies

**中文**:
- **现有订阅API**: `/api/v1/podcasts/subscriptions`
  - 用途: 订阅搜索到的播客
  - 状态: 已实现

- **播客Provider**: `podcastSubscriptionProvider`
  - 用途: 管理订阅状态
  - 状态: 已实现

- **本地存储**: Hive（如实现搜索历史）
  - 用途: 存储搜索历史
  - 状态: 已集成

**English**:
- **Existing Subscription API**: `/api/v1/podcasts/subscriptions`
  - Purpose: Subscribe to searched podcasts
  - Status: Implemented

- **Podcast Provider**: `podcastSubscriptionProvider`
  - Purpose: Manage subscription status
  - Status: Implemented

- **Local Storage**: Hive (if implementing search history)
  - Purpose: Store search history
  - Status: Integrated

## 时间线 / Timeline

### 里程碑 / Milestones

**中文**:
- **需求确认**: 2025-01-02 ✅
- **前端服务层开发**: 2025-01-03
- **前端UI开发**: 2025-01-04
- **集成测试**: 2025-01-05
- **测试完成**: 2025-01-06
- **功能上线**: 2025-01-07

**English**:
- **Requirements Confirmation**: 2025-01-02 ✅
- **Frontend Service Development**: 2025-01-03
- **Frontend UI Development**: 2025-01-04
- **Integration Testing**: 2025-01-05
- **Testing Complete**: 2025-01-06
- **Feature Launch**: 2025-01-07

### 关键路径 / Critical Path

**中文**:
1. 前端服务层实现 (TASK-F-001)
2. 前端搜索组件 (TASK-F-002, TASK-F-003)
3. 集成到播客列表页 (TASK-F-004, TASK-F-005)
4. 测试和验证 (TASK-T-001, TASK-T-002, TASK-T-003)

**English**:
1. Frontend service layer implementation (TASK-F-001)
2. Frontend search components (TASK-F-002, TASK-F-003)
3. Integration to podcast list page (TASK-F-004, TASK-F-005)
4. Testing and validation (TASK-T-001, TASK-T-002, TASK-T-003)

## 变更记录 / Change Log

| 版本 Version | 日期 Date | 变更内容 Changes | 变更人 Changed By | 审批人 Approved By |
|--------------|-----------|------------------|------------------|-------------------|
| 1.3 | 2025-01-02 | 添加国家选择器功能（中国/美国）/ Add country selector (China/USA) | 产品经理 / Product Manager | 待审批 / Pending |
| 1.2 | 2025-01-02 | 明确 Search API 和 Lookup API 使用场景，详细说明 feedUrl 提取流程 / Clarify Search/Lookup API usage, detail feedUrl extraction flow | 产品经理 / Product Manager | 待审批 / Pending |
| 1.1 | 2025-01-02 | 架构调整：改为前端直连iTunes API，删除后端任务 / Architecture change: Frontend calls iTunes API directly, removed backend tasks | 产品经理 / Product Manager | 待审批 / Pending |
| 1.0 | 2025-01-02 | 初始创建 / Initial creation | 产品经理 / Product Manager | 待审批 / Pending |

## 相关文档 / Related Documents

**中文**:
- [播客列表页面实现](../../frontend/lib/features/podcast/presentation/pages/podcast_list_page.dart)
- [播客API路由](../../backend/app/domains/podcast/api/routes.py)
- [Material 3 搜索指南](https://m3.material.io/components/search/overview)
- [iTunes Search API 文档](https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/)
- [iTunes Search API 参考](https://itunes.apple.com/search?term=podcast&media=podcast)

**English**:
- [Podcast List Page Implementation](../../frontend/lib/features/podcast/presentation/pages/podcast_list_page.dart)
- [Podcast API Routes](../../backend/app/domains/podcast/api/routes.py)
- [Material 3 Search Guidelines](https://m3.material.io/components/search/overview)
- [iTunes Search API Documentation](https://affiliate.itunes.apple.com/resources/documentation/itunes-store-web-service-search-api/)
- [iTunes Search API Reference](https://itunes.apple.com/search?term=podcast&media=podcast)

## 审批 / Approval

### 需求评审 / Requirements Review

- [ ] 产品经理审批 / Product Manager Approval
- [ ] 技术负责人审批 / Tech Lead Approval
- [ ] QA负责人审批 / QA Lead Approval

---

**注意 / Note**: 本文档是工作过程中的核心文档，请及时更新并保持版本同步。
This document is the core document during the work process, please update it in time and keep version synchronization.
