import 'package:flutter/material.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';
import '../constants/podcast_ui_constants.dart';

class PodcastSearchResultCard extends StatelessWidget {
  const PodcastSearchResultCard({
    super.key,
    required this.result,
    this.onSubscribe,
    this.isSubscribed = false,
    this.isSubscribing = false,
    this.searchCountry = PodcastCountry.china,
  });

  final PodcastSearchResult result;
  final ValueChanged<PodcastSearchResult>? onSubscribe;
  final bool isSubscribed;
  final bool isSubscribing;
  final PodcastCountry searchCountry;

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    if (result.collectionName == null || result.feedUrl == null) {
      return const SizedBox.shrink();
    }

    return Card(
      margin: const EdgeInsets.symmetric(
        horizontal: kPodcastRowCardHorizontalMargin,
        vertical: kPodcastRowCardVerticalMargin,
      ),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(kPodcastRowCardCornerRadius),
      ),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: () => onSubscribe?.call(result),
        borderRadius: BorderRadius.circular(kPodcastRowCardCornerRadius),
        child: Padding(
          padding: const EdgeInsets.symmetric(
            horizontal: kPodcastRowCardHorizontalPadding,
            vertical: kPodcastRowCardVerticalPadding,
          ),
          child: ConstrainedBox(
            constraints: const BoxConstraints(
              minHeight: kPodcastRowCardImageSize,
            ),
            child: Row(
              children: [
                ClipRRect(
                  borderRadius: BorderRadius.circular(
                    kPodcastRowCardImageRadius,
                  ),
                  child: SizedBox(
                    key: const Key('podcast_search_result_card_artwork'),
                    width: kPodcastRowCardImageSize,
                    height: kPodcastRowCardImageSize,
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
                              if (loadingProgress == null) {
                                return child;
                              }
                              return Container(
                                color: theme.colorScheme.primaryContainer,
                                child: Center(
                                  child: CircularProgressIndicator(
                                    value:
                                        loadingProgress.expectedTotalBytes !=
                                            null
                                        ? loadingProgress
                                                  .cumulativeBytesLoaded /
                                              loadingProgress
                                                  .expectedTotalBytes!
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
                const SizedBox(width: kPodcastRowCardHorizontalGap),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        result.collectionName!,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        result.artistName ?? l10n.podcast_unknown_author,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          if (result.primaryGenreName != null) ...[
                            Icon(
                              Icons.category,
                              size: 14,
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                            const SizedBox(width: 4),
                            Flexible(
                              child: Text(
                                result.primaryGenreName!,
                                style: theme.textTheme.bodySmall?.copyWith(
                                  color: theme.colorScheme.onSurfaceVariant,
                                  fontWeight: FontWeight.w600,
                                ),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
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
                            '${result.trackCount ?? 0} ${l10n.podcast_episodes}',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                              fontWeight: FontWeight.w600,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 6),
                AnimatedSwitcher(
                  duration: const Duration(milliseconds: 300),
                  transitionBuilder: (child, animation) {
                    return FadeTransition(
                      opacity: animation,
                      child: ScaleTransition(scale: animation, child: child),
                    );
                  },
                  child: _buildSubscribeButton(context, l10n, theme),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildSubscribeButton(
    BuildContext context,
    AppLocalizations l10n,
    ThemeData theme,
  ) {
    if (isSubscribed) {
      return Tooltip(
        key: const ValueKey('subscribed'),
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
      );
    }

    if (isSubscribing) {
      return const SizedBox(
        key: ValueKey('subscribing'),
        width: 24,
        height: 24,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    }

    return Tooltip(
      key: const ValueKey('not_subscribed'),
      message: l10n.podcast_subscribe,
      child: IconButton(
        onPressed: () => onSubscribe?.call(result),
        icon: const Icon(Icons.add_circle_outline),
        iconSize: 24,
        color: theme.colorScheme.onSurfaceVariant,
        padding: EdgeInsets.zero,
        constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
      ),
    );
  }
}
