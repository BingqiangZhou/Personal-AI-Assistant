import 'package:flutter/material.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';

/// 播客搜索结果卡片组件
///
/// Material 3 Card 设计，显示播客封面、标题、作者等信息
class PodcastSearchResultCard extends StatelessWidget {
  const PodcastSearchResultCard({
    super.key,
    required this.result,
    this.onSubscribe,
    this.isSubscribed = false,
  });

  final PodcastSearchResult result;
  final ValueChanged<PodcastSearchResult>? onSubscribe;
  final bool isSubscribed;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: () => onSubscribe?.call(result),
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              // 播客封面
              ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: SizedBox(
                  width: 80,
                  height: 80,
                  child: Image.network(
                    result.artworkUrl100,
                    fit: BoxFit.cover,
                    errorBuilder: (context, error, stackTrace) {
                      return Container(
                        color: theme.colorScheme.primaryContainer,
                        child: Center(
                          child: Icon(
                            Icons.podcasts,
                            size: 32,
                            color: theme.colorScheme.onPrimaryContainer,
                          ),
                        ),
                      );
                    },
                    loadingBuilder: (context, child, loadingProgress) {
                      if (loadingProgress == null) return child;
                      return Container(
                        color: theme.colorScheme.primaryContainer,
                        child: Center(
                          child: CircularProgressIndicator(
                            value: loadingProgress.expectedTotalBytes != null
                                ? loadingProgress.cumulativeBytesLoaded /
                                    loadingProgress.expectedTotalBytes!
                                : null,
                          ),
                        ),
                      );
                    },
                  ),
                ),
              ),

              const SizedBox(width: 12),

              // 播客信息
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // 标题
                    Text(
                      result.collectionName,
                      style: theme.textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),

                    const SizedBox(height: 4),

                    // 作者
                    Text(
                      result.artistName,
                      style: theme.textTheme.bodyMedium?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),

                    const SizedBox(height: 4),

                    // 分类和集数
                    Row(
                      children: [
                        if (result.primaryGenreName != null) ...[
                          Icon(
                            Icons.category,
                            size: 14,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: 4),
                          Text(
                            result.primaryGenreName!,
                            style: theme.textTheme.labelSmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(width: 8),
                        ],
                        Icon(
                          Icons.podcasts,
                          size: 14,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          '${result.trackCount} ${l10n.podcast_episodes}',
                          style: theme.textTheme.labelSmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),

              const SizedBox(width: 8),

              // 订阅状态图标（根据订阅状态显示不同样式）
              isSubscribed
                  ? Tooltip(
                      message: l10n.podcast_subscribed,
                      child: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Icon(
                          Icons.check_circle,
                          color: theme.colorScheme.primary,
                          size: 32,
                        ),
                      ),
                    )
                  : Tooltip(
                      message: l10n.podcast_subscribe,
                      child: IconButton(
                        onPressed: () => onSubscribe?.call(result),
                        icon: const Icon(Icons.add_circle_outline),
                        iconSize: 32,
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
            ],
          ),
        ),
      ),
    );
  }
}
