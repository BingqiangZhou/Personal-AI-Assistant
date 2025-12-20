import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../providers/podcast_providers.dart';

class PodcastEpisodeDetailPage extends ConsumerStatefulWidget {
  final int episodeId;

  const PodcastEpisodeDetailPage({
    super.key,
    required this.episodeId,
  });

  @override
  ConsumerState<PodcastEpisodeDetailPage> createState() => _PodcastEpisodeDetailPageState();
}

class _PodcastEpisodeDetailPageState extends ConsumerState<PodcastEpisodeDetailPage> {
  bool _isTranscriptTab = true; // true = 文字转录, false = 节目简介
  double _currentProgress = 0.3; // 模拟播放进度 (30%)
  bool _isPlaying = false;
  double _playbackSpeed = 1.0;

  // 模拟转录对话数据（根据用户要求的精确格式）
  final List<Map<String, String>> _dialogueItems = [
    {'speaker': '主持人', 'time': '00:00', 'content': '大家好，欢迎收听本期节目。今天我们来聊聊AI应用的最新发展。'},
    {'speaker': '嘉宾A', 'time': '00:15', 'content': '很高兴来到这里。AI技术确实在快速发展，特别是在自然语言处理领域。'},
    {'speaker': '主持人', 'time': '00:32', 'content': '没错，我们看到很多创新应用。能分享一下你们的具体实践吗？'},
    {'speaker': '嘉宾B', 'time': '00:48', 'content': '当然。我们主要关注企业级应用，帮助客户提升效率的同时降低成本。'},
    {'speaker': '主持人', 'time': '01:05', 'content': '听起来很有价值。听众朋友们，如果你们有任何问题，欢迎在评论区留言。'},
  ];

  @override
  Widget build(BuildContext context) {
    final episodeDetailAsync = ref.watch(episodeDetailProvider(widget.episodeId));

    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      body: episodeDetailAsync.when(
        data: (episodeDetail) {
          if (episodeDetail == null) {
            return _buildErrorState(context, 'Episode not found');
          }
          return _buildNewLayout(context, episodeDetail);
        },
        loading: () => const Center(child: CircularProgressIndicator()),
        error: (error, stack) => _buildErrorState(context, error),
      ),
      bottomNavigationBar: _buildBottomPlayer(context),
    );
  }

  // 新的页面布局
  Widget _buildNewLayout(BuildContext context, dynamic episode) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final isWideScreen = constraints.maxWidth > 840;

        return Column(
          children: [
            // A. 顶部元数据区 (Header)
            _buildHeader(episode),

            // B. 中间主体内容区 (Body - 响应式布局)
            Expanded(
              child: isWideScreen
                  ? Row(
                      children: [
                        // 左侧主内容 (Flex 7)
                        Expanded(
                          flex: 7,
                          child: _buildMainContent(episode),
                        ),
                        // 右侧侧边栏 (Flex 3)
                        Expanded(
                          flex: 3,
                          child: _buildSidebar(episode),
                        ),
                      ],
                    )
                  : _buildMainContent(episode),
            ),
          ],
        );
      },
    );
  }

  // A. 顶部元数据区 (Header) - 无底部分割线
  Widget _buildHeader(dynamic episode) {
    return Container(
      padding: const EdgeInsets.all(16),
      color: Theme.of(context).colorScheme.surface,
      child: Row(
        children: [
          // 左侧：返回按钮 + Logo + 文本
          Expanded(
            child: Row(
              children: [
                // 返回按钮
                Container(
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: IconButton(
                    icon: Icon(
                      Icons.arrow_back,
                      color: Theme.of(context).colorScheme.primary,
                      size: 20,
                    ),
                    onPressed: () => context.pop(),
                    tooltip: '返回',
                    constraints: const BoxConstraints(
                      minWidth: 36,
                      minHeight: 36,
                    ),
                    padding: EdgeInsets.zero,
                  ),
                ),
                const SizedBox(width: 12),
                // Logo: 50x50px, 主题色背景, 圆角8px, Icons.podcasts
                Container(
                  width: 50,
                  height: 50,
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                      width: 1,
                    ),
                  ),
                  child: Icon(Icons.podcasts, color: Theme.of(context).colorScheme.primary, size: 28),
                ),
                const SizedBox(width: 12),
                // 文本：垂直排列的Column
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // 标题: 16px, FontWeight.bold, 主题色
                      Text(
                        episode.title ?? 'Unknown Episode',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.onSurface,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      // 副标题: 12px, 次要文字颜色, 单行省略
                      Text(
                        episode.description?.substring(0, min(40, episode.description?.length ?? 0)) ?? 'No description',
                        style: TextStyle(
                          fontSize: 12,
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          // 右侧：总时长 (14px, 次要文字颜色, FontWeight.w500)
          Text(
            episode.formattedDuration ?? '3:00',
            style: TextStyle(
              fontSize: 14,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
              fontWeight: FontWeight.w500,
            ),
          ),
        ],
      ),
    );
  }

  // B. 左侧主内容
  Widget _buildMainContent(dynamic episode) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        children: [
          // Tabs：文字转录 / 节目简介
          _buildTabs(),

          // 内容区域
          Expanded(
            child: _isTranscriptTab
                ? _buildTranscriptContent(episode)
                : _buildDescriptionContent(episode),
          ),
        ],
      ),
    );
  }

  // Tabs 组件 - 胶囊状按钮
  Widget _buildTabs() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(color: Theme.of(context).colorScheme.outlineVariant, width: 1),
        ),
      ),
      child: Row(
        children: [
          // 文字转录 Tab
          _buildTabButton('文字转录', _isTranscriptTab, () {
            setState(() {
              _isTranscriptTab = true;
            });
          }),
          const SizedBox(width: 8),
          // 节目简介 Tab
          _buildTabButton('节目简介', !_isTranscriptTab, () {
            setState(() {
              _isTranscriptTab = false;
            });
          }),
        ],
      ),
    );
  }

  // Tab 按钮组件 - 胶囊状
  Widget _buildTabButton(String text, bool isSelected, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        decoration: BoxDecoration(
          color: isSelected ? Theme.of(context).colorScheme.primary : Colors.transparent,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: isSelected ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.outline,
            width: 1,
          ),
        ),
        child: Text(
          text,
          style: TextStyle(
            color: isSelected ? Theme.of(context).colorScheme.onPrimary : Theme.of(context).colorScheme.onSurfaceVariant,
            fontSize: 13,
            fontWeight: isSelected ? FontWeight.w600 : FontWeight.w500,
          ),
        ),
      ),
    );
  }

  // 文字转录内容 - 多人对话脚本
  Widget _buildTranscriptContent(dynamic episode) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: ListView.builder(
        itemCount: _dialogueItems.length,
        itemBuilder: (context, index) {
          final item = _dialogueItems[index];
          return Column(
            children: [
              _buildDialogueItem(
                item['speaker']!,
                item['content']!,
                item['time']!,
              ),
              if (index < _dialogueItems.length - 1) const SizedBox(height: 16),
            ],
          );
        },
      ),
    );
  }

  // 对话项组件
  Widget _buildDialogueItem(String speaker, String content, String time) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(
                  color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.3),
                  width: 1,
                ),
              ),
              child: Text(
                speaker,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: Theme.of(context).colorScheme.primary,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              time,
              style: TextStyle(
                fontSize: 11,
                color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.6),
              ),
            ),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          content,
          style: TextStyle(
            fontSize: 15,
            height: 1.6,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
      ],
    );
  }

  // 节目简介内容
  Widget _buildDescriptionContent(dynamic episode) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Text(
        episode.aiSummary ?? '这是一期关于AI技术应用的深度讨论节目。我们邀请了行业专家，分享了他们在实际项目中的经验和见解。内容涵盖了从技术架构到商业应用的各个方面，对于想要了解AI落地实践的听众来说非常有价值。',
        style: TextStyle(
          fontSize: 15,
          height: 1.8,
          color: Theme.of(context).colorScheme.onSurface,
        ),
      ),
    );
  }

  // B. 右侧侧边栏 - 只有节目AI总结
  Widget _buildSidebar(dynamic episode) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      padding: const EdgeInsets.all(16),
      child: _buildSidebarSection(
        '节目AI总结',
        episode.aiSummary ?? '这是一期关于AI技术应用的深度讨论节目。我们邀请了行业专家，分享了他们在实际项目中的经验和见解。内容涵盖了从技术架构到商业应用的各个方面，对于想要了解AI落地实践的听众来说非常有价值。',
      ),
    );
  }

  // 侧边栏通用部分组件
  Widget _buildSidebarSection(String title, String content) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          content,
          style: TextStyle(
            fontSize: 13,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
            height: 1.5,
          ),
        ),
      ],
    );
  }

  // C. 底部沉浸式播放条
  Widget _buildBottomPlayer(BuildContext context) {
    return Container(
      color: Theme.of(context).colorScheme.surface,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // 1. 进度条 - 横跨整个宽度，细轨道
          _buildProgressBar(),

          // 2. 控制区
          _buildControlArea(),
        ],
      ),
    );
  }

  // 进度条 - 轨道高度2px，主题色
  Widget _buildProgressBar() {
    return Slider(
      value: _currentProgress,
      onChanged: (value) {
        setState(() {
          _currentProgress = value;
        });
      },
      min: 0,
      max: 1,
      activeColor: Theme.of(context).colorScheme.primary,
      inactiveColor: Theme.of(context).colorScheme.outline,
      thumbColor: Theme.of(context).colorScheme.primary,
      overlayColor: WidgetStateProperty.all(Theme.of(context).colorScheme.primary.withValues(alpha: 0.1)),
    );
  }

  // 控制区
  Widget _buildControlArea() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          // 左边：当前时间 + 音量图标
          Row(
            children: [
              Text(
                _formatTime(_currentProgress * 180), // 假设总时长3分钟
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              const SizedBox(width: 8),
              Icon(
                Icons.volume_up,
                size: 18,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ],
          ),

          // 中间：播放控制组
          Row(
            children: [
              // 回退15s
              GestureDetector(
                onTap: () {
                  print('回退15s');
                  setState(() {
                    _currentProgress = (_currentProgress - 0.083).clamp(0.0, 1.0);
                  });
                },
                child: Container(
                  padding: const EdgeInsets.all(4),
                  child: Icon(
                    Icons.replay_10, // 使用10s图标作为近似
                    size: 24,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              const SizedBox(width: 12),

              // 播放/暂停主按钮 - 圆形，黑色图标
              GestureDetector(
                onTap: () {
                  setState(() {
                    _isPlaying = !_isPlaying;
                  });
                  print(_isPlaying ? '播放' : '暂停');
                },
                child: Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primary,
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.2),
                        blurRadius: 8,
                        offset: const Offset(0, 2),
                      ),
                    ],
                  ),
                  child: Icon(
                    _isPlaying ? Icons.pause : Icons.play_arrow,
                    color: Theme.of(context).colorScheme.onPrimary,
                    size: 28,
                  ),
                ),
              ),
              const SizedBox(width: 12),

              // 前进30s
              GestureDetector(
                onTap: () {
                  print('前进30s');
                  setState(() {
                    _currentProgress = (_currentProgress + 0.167).clamp(0.0, 1.0);
                  });
                },
                child: Container(
                  padding: const EdgeInsets.all(4),
                  child: Icon(
                    Icons.forward_30,
                    size: 24,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ],
          ),

          // 右边：总时间 + 倍速按钮（圆角矩形边框）
          Row(
            children: [
              Text(
                '3:00',
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              const SizedBox(width: 8),
              GestureDetector(
                onTap: () {
                  setState(() {
                    _playbackSpeed = _playbackSpeed == 1.0 ? 1.5 : (_playbackSpeed == 1.5 ? 2.0 : 1.0);
                  });
                  print('倍速: $_playbackSpeed');
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    border: Border.all(color: Theme.of(context).colorScheme.outline),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    '${_playbackSpeed}x',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // 工具方法：格式化时间
  String _formatTime(double seconds) {
    final totalSeconds = seconds.round();
    final minutes = totalSeconds ~/ 60;
    final remainingSeconds = totalSeconds % 60;
    return '$minutes:${remainingSeconds.toString().padLeft(2, '0')}';
  }

  // 工具方法：取最小值
  int min(int a, int b) => a < b ? a : b;

  // 错误状态
  Widget _buildErrorState(BuildContext context, dynamic error) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(
            Icons.error_outline,
            size: 64,
            color: Colors.red,
          ),
          const SizedBox(height: 16),
          Text(
            'Error loading episode',
            style: Theme.of(context).textTheme.titleMedium,
          ),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text(
              error.toString(),
              textAlign: TextAlign.center,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                    color: Colors.grey[600],
                  ),
            ),
          ),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: () {
              context.pop();
            },
            child: const Text('Go Back'),
          ),
        ],
      ),
    );
  }
}
