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
    this.searchCountry = PodcastCountry.china,
  });

  final PodcastSearchResult result;
  final ValueChanged<PodcastSearchResult>? onSubscribe;
  final bool isSubscribed;
  final PodcastCountry searchCountry;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    // 如果缺少必要字段，不显示此卡片
    if (result.collectionName == null || result.feedUrl == null) {
      return const SizedBox.shrink();
    }

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: () => onSubscribe?.call(result),
        child: Padding(
          padding: const EdgeInsets.all(8),
          child: Row(
            children: [
              // 播客封面
              ClipRRect(
                borderRadius: BorderRadius.circular(6),
                child: SizedBox(
                  width: 56,
                  height: 56,
                  child: result.artworkUrl100 != null
                      ? Image.network(
                          result.artworkUrl100!,
                          fit: BoxFit.cover,
                          errorBuilder: (context, error, stackTrace) {
                            return Container(
                              color: theme.colorScheme.primaryContainer,
                              child: Center(
                                child: Icon(
                                  Icons.podcasts,
                                  size: 24,
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
                                  strokeWidth: 2,
                                ),
                              ),
                            );
                          },
                        )
                      : Container(
                          color: theme.colorScheme.primaryContainer,
                          child: Center(
                            child: Icon(
                              Icons.podcasts,
                              size: 24,
                              color: theme.colorScheme.onPrimaryContainer,
                            ),
                          ),
                        ),
                ),
              ),

              const SizedBox(width: 10),

              // 播客信息
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // 标题（使用更小的字体）
                    Text(
                      result.collectionName!,
                      style: theme.textTheme.titleSmall?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),

                    const SizedBox(height: 2),

                    // 作者（使用更小的字体）
                    Text(
                      result.artistName ?? l10n.podcast_unknown_author,
                      style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),

                    const SizedBox(height: 2),

                    // 分类和集数（使用更小的图标和字体）
                    Row(
                      children: [
                        if (result.primaryGenreName != null) ...[
                          Icon(
                            Icons.category,
                            size: 12,
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                          const SizedBox(width: 3),
                          Text(
                            result.primaryGenreName!,
                            style: theme.textTheme.labelSmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                  fontSize: 11,
                                ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(width: 6),
                        ],
                        Icon(
                          Icons.podcasts,
                          size: 12,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                        const SizedBox(width: 3),
                        Text(
                          '${result.trackCount ?? 0} ${l10n.podcast_episodes}',
                          style: theme.textTheme.labelSmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                                fontSize: 11,
                              ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),

              const SizedBox(width: 6),

              // 订阅状态图标（缩小尺寸）
              isSubscribed
                  ? Tooltip(
                      message: l10n.podcast_subscribed,
                      child: Container(
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Icon(
                          Icons.check_circle,
                          color: theme.colorScheme.primary,
                          size: 24,
                        ),
                      ),
                    )
                  : Tooltip(
                      message: l10n.podcast_subscribe,
                      child: IconButton(
                        onPressed: () => onSubscribe?.call(result),
                        icon: const Icon(Icons.add_circle_outline),
                        iconSize: 24,
                        color: theme.colorScheme.onSurfaceVariant,
                        padding: EdgeInsets.zero,
                        constraints: const BoxConstraints(
                          minWidth: 36,
                          minHeight: 36,
                        ),
                      ),
                    ),
            ],
          ),
        ),
      ),
    );
  }
}
