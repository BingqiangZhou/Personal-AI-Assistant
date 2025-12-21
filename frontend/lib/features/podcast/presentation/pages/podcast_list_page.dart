import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../providers/podcast_providers.dart';
import '../widgets/add_podcast_dialog.dart';

/// Material Design 3自适应播客列表页面
class PodcastListPage extends StatelessWidget {
  const PodcastListPage({super.key});

  @override
  Widget build(BuildContext context) {
    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题和操作区域
          Row(
            children: [
              Expanded(
                child: Text(
                  'Podcasts',
                  style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                ),
              ),
              const SizedBox(width: 16),
              FilledButton.tonal(
                onPressed: () {
                  // TODO: 显示添加播客对话框
                },
                child: const Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.add, size: 16),
                    SizedBox(width: 4),
                    Text('Add Podcast'),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // 搜索和筛选栏
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    decoration: InputDecoration(
                      hintText: 'Search podcasts...',
                      prefixIcon: const Icon(Icons.search),
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(8),
                      ),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                IconButton.filled(
                  onPressed: () {
                    // TODO: 实现筛选功能
                  },
                  icon: const Icon(Icons.filter_list),
                  tooltip: 'Filter',
                ),
                IconButton.filled(
                  onPressed: () {
                    // TODO: 实现刷新功能
                  },
                  icon: const Icon(Icons.refresh),
                  tooltip: 'Refresh',
                ),
              ],
            ),
          ),

          const SizedBox(height: 24),

          // 播客列表内容
          Expanded(
            child: Consumer(
              builder: (context, ref, child) {
                return _buildSubscriptionContent(context, ref);
              },
            ),
          ),
        ],
      ),
    );
  }

  
  /// 构建订阅内容
  Widget _buildSubscriptionContent(BuildContext context, WidgetRef ref) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // 暂时显示静态数据，用于测试UI
    return _buildMockPodcastList(context, isMobile);

    // TODO: 修复数据加载后启用这个代码
    /*
    final subscriptionsAsync = ref.watch(podcastSubscriptionProvider);

    return subscriptionsAsync.when(
      data: (response) {
        if (response.subscriptions.isEmpty) {
          return _buildEmptyState(context, isMobile);
        }
        return _buildPodcastList(context, response.subscriptions, isMobile);
      },
      loading: () => _buildLoadingState(context),
      error: (error, stack) => _buildErrorState(context, error),
    );
    */
  }

  /// 模拟播客列表（用于UI测试）
  Widget _buildMockPodcastList(BuildContext context, bool isMobile) {
    // 模拟数据
    final mockPodcasts = [
      {'title': 'The Tech Podcast', 'description': 'Latest in technology and innovation'},
      {'title': 'AI Insights', 'description': 'Deep dives into artificial intelligence'},
      {'title': 'Startup Stories', 'description': 'Entrepreneurship and business growth'},
      {'title': 'Design Matters', 'description': 'Design thinking and creativity'},
      {'title': 'DevOps Daily', 'description': 'Software development and operations'},
    ];

    if (isMobile) {
      return RefreshIndicator(
        onRefresh: () async {
          // TODO: 实现刷新逻辑
        },
        child: ListView.builder(
          padding: const EdgeInsets.symmetric(vertical: 16),
          itemCount: mockPodcasts.length,
          itemBuilder: (context, index) {
            final podcast = mockPodcasts[index];
            return Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              child: Card(
                child: ListTile(
                  leading: CircleAvatar(
                    backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                    child: Icon(
                      Icons.podcasts,
                      color: Theme.of(context).colorScheme.onPrimaryContainer,
                    ),
                  ),
                  title: Text(podcast['title']!),
                  subtitle: Text(podcast['description']!),
                  trailing: const Icon(Icons.more_vert),
                  onTap: () {
                    // TODO: 实现播客详情导航
                  },
                ),
              ),
            );
          },
        ),
      );
    } else {
      // 桌面端网格布局
      return ResponsiveGrid(
        crossAxisSpacing: 16,
        mainAxisSpacing: 16,
        childAspectRatio: 3.0,
        children: mockPodcasts.map((podcast) {
          return Card(
            child: ListTile(
              leading: CircleAvatar(
                backgroundColor: Theme.of(context).colorScheme.primaryContainer,
                child: Icon(
                  Icons.podcasts,
                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                ),
              ),
              title: Text(podcast['title']!),
              subtitle: Text(podcast['description']!),
              trailing: const Icon(Icons.more_vert),
              onTap: () {
                // TODO: 实现播客详情导航
              },
            ),
          );
        }).toList(),
      );
    }
  }

  /// 加载状态
  Widget _buildLoadingState(BuildContext context) {
    return const Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          CircularProgressIndicator(),
          SizedBox(height: 16),
          Text('Loading podcasts...'),
        ],
      ),
    );
  }

  /// 错误状态
  Widget _buildErrorState(BuildContext context, Object error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.error_outline,
            size: 64,
            color: Theme.of(context).colorScheme.error,
          ),
          const SizedBox(height: 16),
          Text(
            'Failed to load podcasts',
            style: Theme.of(context).textTheme.headlineSmall,
          ),
          const SizedBox(height: 8),
          Text(
            error.toString(),
            style: Theme.of(context).textTheme.bodyMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 24),
          FilledButton.icon(
            onPressed: () {
              // TODO: 实现重试逻辑
            },
            icon: const Icon(Icons.refresh),
            label: const Text('Retry'),
          ),
        ],
      ),
    );
  }

  /// 刷新订阅
  Future<void> _refreshSubscriptions(WidgetRef ref) async {
    await ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
  }

  /// 显示添加播客对话框
  void _showAddPodcastDialog(BuildContext context, WidgetRef? ref) {
    showDialog(
      context: context,
      builder: (context) => const AddPodcastDialog(),
    );
  }

  /// 构建空状态
  Widget _buildEmptyState(BuildContext context, bool isMobile) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            padding: const EdgeInsets.all(24),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primaryContainer,
              shape: BoxShape.circle,
            ),
            child: Icon(
              Icons.podcasts_outlined,
              size: isMobile ? 64 : 80,
              color: Theme.of(context).colorScheme.onPrimaryContainer,
            ),
          ),
          const SizedBox(height: 24),
          Text(
            'No Podcasts Yet',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 12),
          Text(
            'Add your first podcast to get started',
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 32),
          FilledButton.icon(
            onPressed: () => _showAddPodcastDialog(context, null),
            icon: const Icon(Icons.add),
            label: const Text('Add Podcast'),
          ),
        ],
      ),
    );
  }

  }