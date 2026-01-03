# 需求文档：播客分集详情页链接功能

## 需求概述 / Overview

为播客分集添加详情页链接功能，允许用户点击分集标题打开对应的网页（如播客平台的分集详情页）。

## 用户故事 / User Story

**作为** 播客听众
**我想要** 点击分集标题打开分集详情页
**这样** 我可以在原平台查看更多内容、参与评论或进行其他操作

## 验收标准 / Acceptance Criteria

- [ ] 后端解析并存储 RSS `<item><link>` 标签内容
- [ ] 前端分集卡片标题可点击打开链接
- [ ] 分集标题旁显示可点击图标（如：🔗 或 Icons.link）
- [ ] 链接在浏览器中正确打开
- [ ] 兼容没有 link 字段的分集（不显示点击功能）

## 技术要求 / Technical Requirements

### 后端变更
1. 数据库添加 `podcast_episodes.item_link` 字段（可空）
2. RSS解析器解析 `<item><link>` 标签
3. API Schema 返回 `item_link` 字段
4. 数据库迁移脚本

### 前端变更
1. `PodcastEpisodeModel` 添加 `itemLink` 字段
2. 分集卡片组件添加链接点击功能
3. 使用 `url_launcher` 打开外部链接
4. 添加链接图标提示

### 设计规范
- 图标位置：标题右侧
- 图标样式：Material `Icons.link` 或 `Icons.open_in_browser`
- 颜色：主题色或灰色
- 交互：整个标题区域可点击

## 优先级 / Priority

**Medium** - 增强用户体验，方便用户跳转到原平台

## 技术方案 / Technical Approach

### 后端实现
```python
# 添加字段
item_link = Column(String(500), nullable=True)

# 解析器
link = self._safe_text(item.findtext('link', ''))
```

### 前端实现
```dart
// 模型
@JsonKey(name: 'item_link')
final String? itemLink;

// UI
InkWell(
  onTap: () => launchUrl(Uri.parse(episode.itemLink)),
  child: Row(
    children: [
      Text(episode.title),
      Icon(Icons.link, size: 16),
    ],
  ),
)
```

## 相关文件 / Related Files

- `backend/app/domains/podcast/models.py`
- `backend/app/integration/podcast/secure_rss_parser.py`
- `backend/app/domains/podcast/schemas.py`
- `frontend/lib/features/podcast/data/models/podcast_episode_model.dart`
- `frontend/lib/features/podcast/presentation/widgets/simplified_episode_card.dart`
