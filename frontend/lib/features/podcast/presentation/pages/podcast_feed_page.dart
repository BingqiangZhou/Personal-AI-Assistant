import 'package:flutter/material.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';

/// Material Design 3自适应Feed页面
class PodcastFeedPage extends StatelessWidget {
  const PodcastFeedPage({super.key});

  @override
  Widget build(BuildContext context) {
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题
          Text(
            'Feed',
            style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                  fontWeight: FontWeight.bold,
                ),
          ),
          const SizedBox(height: 24),

          // Feed内容 - 直接使用Expanded填充剩余空间
          Expanded(
            child: _buildFeedContent(context),
          ),
        ],
      ),
    );
  }

  /// 构建Feed内容
  Widget _buildFeedContent(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // 暂时显示静态数据，用于测试UI
    return _buildMockFeed(context, isMobile);
  }

  /// 模拟Feed内容（用于UI测试）- 优化布局，避免溢出
  Widget _buildMockFeed(BuildContext context, bool isMobile) {
    // 模拟数据
    final mockEpisodes = [
      {
        'title': 'The Future of AI in Software Development',
        'podcast': 'Tech Talks Daily',
        'description': 'Exploring how artificial intelligence is transforming the way we write code and software',
        'duration': '45 min',
        'published': '2 hours ago',
        'isPlayed': false,
      },
      {
        'title': 'Building Scalable Microservices',
        'podcast': 'Engineering Podcast',
        'description': 'Best practices for designing and implementing microservice architectures that can scale',
        'duration': '38 min',
        'published': '5 hours ago',
        'isPlayed': true,
      },
      {
        'title': 'The Psychology of Product Design',
        'podcast': 'Design Insights',
        'description': 'Understanding user behavior and cognitive biases to create better products',
        'duration': '52 min',
        'published': '1 day ago',
        'isPlayed': false,
      },
      {
        'title': 'Startup Funding Strategies',
        'podcast': 'Entrepreneur Weekly',
        'description': 'From seed rounds to Series A, navigating the complex world of startup financing',
        'duration': '41 min',
        'published': '2 days ago',
        'isPlayed': false,
      },
      {
        'title': 'Clean Code Principles',
        'podcast': 'Dev Masters',
        'description': 'Essential principles for writing maintainable, readable, and robust code',
        'duration': '35 min',
        'published': '3 days ago',
        'isPlayed': true,
      },
    ];

    // 使用LayoutBuilder来动态调整布局
    return LayoutBuilder(
      builder: (context, constraints) {
        final screenWidth = constraints.maxWidth;

        // 移动端：使用ListView
        if (screenWidth < 600) {
          return RefreshIndicator(
            onRefresh: () async {
              // TODO: 实现刷新逻辑
            },
            child: ListView.builder(
              padding: const EdgeInsets.symmetric(vertical: 12),
              itemCount: mockEpisodes.length,
              itemBuilder: (context, index) {
                return _buildMobileCard(context, mockEpisodes[index]);
              },
            ),
          );
        }

        // 桌面端：使用GridView，优化卡片高度
        final crossAxisCount = screenWidth < 900 ? 2 : (screenWidth < 1200 ? 3 : 4);
        final horizontalPadding = 48.0;
        final spacing = 16.0;
        final availableWidth = screenWidth - horizontalPadding - (crossAxisCount - 1) * spacing;
        final cardWidth = availableWidth / crossAxisCount;

        // 优化宽高比：卡片内容高度约180-200，确保不溢出
        final childAspectRatio = cardWidth / 200;

        return RefreshIndicator(
          onRefresh: () async {
            // TODO: 实现刷新逻辑
          },
          child: GridView.builder(
            padding: const EdgeInsets.symmetric(vertical: 12),
            gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: crossAxisCount,
              crossAxisSpacing: spacing,
              mainAxisSpacing: spacing,
              childAspectRatio: childAspectRatio,
            ),
            itemCount: mockEpisodes.length,
            itemBuilder: (context, index) {
              return _buildDesktopCard(context, mockEpisodes[index]);
            },
          ),
        );
      },
    );
  }

  /// 构建移动端卡片
  Widget _buildMobileCard(BuildContext context, Map<String, dynamic> episode) {
    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      child: InkWell(
        onTap: () {
          // TODO: 实现播客详情导航
        },
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 播放按钮
                  Container(
                    width: 48,
                    height: 48,
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primaryContainer,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      episode['isPlayed'] == true
                          ? Icons.play_arrow
                          : Icons.play_circle_filled,
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                      size: 28,
                    ),
                  ),
                  const SizedBox(width: 16),
                  // 标题和信息
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          episode['title'] as String,
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 4),
                        Text(
                          episode['podcast'] as String,
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: Theme.of(context).colorScheme.primary,
                                fontWeight: FontWeight.w500,
                              ),
                        ),
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 16,
                          runSpacing: 4,
                          children: [
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.schedule,
                                  size: 16,
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  episode['duration'] as String,
                                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                                      ),
                                ),
                              ],
                            ),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                Icon(
                                  Icons.access_time,
                                  size: 16,
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  episode['published'] as String,
                                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                                      ),
                                ),
                              ],
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              if (episode['description'] != null) ...[
                const SizedBox(height: 12),
                Text(
                  episode['description'] as String,
                  style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                  maxLines: 3,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
              const SizedBox(height: 12),
              // 操作按钮 - 使用Wrap避免溢出
              Wrap(
                alignment: WrapAlignment.end,
                spacing: 8,
                runSpacing: 8,
                children: [
                  IconButton.filled(
                    onPressed: () {
                      // TODO: 实现收藏功能
                    },
                    icon: const Icon(Icons.bookmark_border),
                    tooltip: 'Bookmark',
                    style: IconButton.styleFrom(
                      backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                      foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                      minimumSize: const Size(40, 40),
                      padding: const EdgeInsets.all(8),
                    ),
                  ),
                  IconButton.filled(
                    onPressed: () {
                      // TODO: 实现分享功能
                    },
                    icon: const Icon(Icons.share),
                    tooltip: 'Share',
                    style: IconButton.styleFrom(
                      backgroundColor: Theme.of(context).colorScheme.surfaceContainerHighest,
                      foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
                      minimumSize: const Size(40, 40),
                      padding: const EdgeInsets.all(8),
                    ),
                  ),
                  FilledButton.tonal(
                    onPressed: () {
                      // TODO: 实现播放功能
                    },
                    child: const Text('Play'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  /// 构建桌面端卡片（优化布局，避免溢出）
  Widget _buildDesktopCard(BuildContext context, Map<String, dynamic> episode) {
    return Card(
      child: InkWell(
        onTap: () {
          // TODO: 实现播客详情导航
        },
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // 第一行：播放按钮 + 标题信息
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // 播放按钮
                  Container(
                    width: 44,
                    height: 44,
                    decoration: BoxDecoration(
                      color: Theme.of(context).colorScheme.primaryContainer,
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      episode['isPlayed'] == true
                          ? Icons.play_arrow
                          : Icons.play_circle_filled,
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                      size: 22,
                    ),
                  ),
                  const SizedBox(width: 10),
                  // 标题和播客名
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          episode['title'] as String,
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                fontWeight: FontWeight.w600,
                              ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 2),
                        Text(
                          episode['podcast'] as String,
                          style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                color: Theme.of(context).colorScheme.primary,
                                fontWeight: FontWeight.w500,
                              ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),
                ],
              ),

              // 描述
              if (episode['description'] != null) ...[
                const SizedBox(height: 8),
                Expanded(
                  child: Text(
                    episode['description'] as String,
                    style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],

              // 元数据和操作按钮
              const SizedBox(height: 8),
              Row(
                children: [
                  // 时间信息
                  Expanded(
                    child: Wrap(
                      spacing: 10,
                      runSpacing: 4,
                      children: [
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.schedule,
                              size: 13,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 2),
                            Text(
                              episode['duration'] as String,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(
                              Icons.access_time,
                              size: 13,
                              color: Theme.of(context).colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 2),
                            Text(
                              episode['published'] as String,
                              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),

                  // Play 按钮
                  const SizedBox(width: 8),
                  FilledButton.tonal(
                    onPressed: () {
                      // TODO: 实现播放功能
                    },
                    child: const Text('Play'),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}