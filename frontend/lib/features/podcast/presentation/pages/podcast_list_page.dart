import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../providers/podcast_providers.dart';
import '../widgets/add_podcast_dialog.dart';
import '../widgets/bulk_import_dialog.dart';

/// Material Design 3自适应播客列表页面
class PodcastListPage extends ConsumerStatefulWidget {
  const PodcastListPage({super.key});

  @override
  ConsumerState<PodcastListPage> createState() => _PodcastListPageState();
}

class _PodcastListPageState extends ConsumerState<PodcastListPage> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
    });
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;

    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题和操作区域
          LayoutBuilder(builder: (context, constraints) {
            final isNarrow = constraints.maxWidth < 500;
            return Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        l10n.podcast_title,
                        style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                              fontWeight: FontWeight.bold,
                            ),
                      ),
                    ),
                    if (!isNarrow) ...[
                      FilledButton.icon(
                        onPressed: () {
                          showDialog(
                            context: context,
                            builder: (context) => const AddPodcastDialog(),
                          );
                        },
                        style: FilledButton.styleFrom(
                          backgroundColor: Theme.of(context).colorScheme.secondary,
                          foregroundColor: Theme.of(context).colorScheme.onSecondary,
                        ),
                        icon: const Icon(Icons.add),
                        label: Text(l10n.podcast_add_podcast),
                      ),
                      const SizedBox(width: 8),
                      FilledButton.icon(
                        onPressed: () {
                          showDialog(
                            context: context,
                            builder: (context) => BulkImportDialog(
                              onImport: (urls) async {
                                await ref
                                    .read(podcastSubscriptionProvider.notifier)
                                    .addSubscriptionsBatch(feedUrls: urls);
                              },
                            ),
                          );
                        },
                        style: FilledButton.styleFrom(
                          backgroundColor: Theme.of(context).colorScheme.tertiary,
                          foregroundColor: Theme.of(context).colorScheme.onTertiary,
                        ),
                        icon: const Icon(Icons.playlist_add),
                        label: Text(l10n.podcast_bulk_import),
                      ),
                    ],
                  ],
                ),
                if (isNarrow) ...[
                  const SizedBox(height: 16),
                  Row(
                    children: [
                      Expanded(
                        child: FilledButton.icon(
                          onPressed: () {
                            showDialog(
                              context: context,
                              builder: (context) => const AddPodcastDialog(),
                            );
                          },
                          style: FilledButton.styleFrom(
                            backgroundColor: Theme.of(context).colorScheme.secondary,
                            foregroundColor: Theme.of(context).colorScheme.onSecondary,
                          ),
                          icon: const Icon(Icons.add),
                          label: Text(l10n.add),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: FilledButton.icon(
                          onPressed: () {
                            showDialog(
                              context: context,
                              builder: (context) => BulkImportDialog(
                                onImport: (urls) async {
                                  await ref
                                      .read(podcastSubscriptionProvider.notifier)
                                      .addSubscriptionsBatch(feedUrls: urls);
                                },
                              ),
                            );
                          },
                          style: FilledButton.styleFrom(
                            backgroundColor: Theme.of(context).colorScheme.tertiary,
                            foregroundColor: Theme.of(context).colorScheme.onTertiary,
                          ),
                          icon: const Icon(Icons.playlist_add),
                          label: Text(l10n.podcast_bulk_import),
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            );
          }),
          const SizedBox(height: 24),

          // 订阅列表
          Expanded(
            child: _buildSubscriptionContent(context),
          ),
        ],
      ),
    );
  }

  Widget _buildSubscriptionContent(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    // Note: using podcastSubscriptionProvider instead of podcastSubscriptionProvider
    final subscriptionsState = ref.watch(podcastSubscriptionProvider);
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    return subscriptionsState.when(
      data: (response) {
        if (response.subscriptions.isEmpty) {
          return Center(
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  Icons.podcasts,
                  size: 64,
                  color: Theme.of(context).colorScheme.outlineVariant,
                ),
                const SizedBox(height: 16),
                Text(
                  l10n.podcast_no_podcasts,
                  style: Theme.of(context).textTheme.titleLarge?.copyWith(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                ),
                const SizedBox(height: 8),
                TextButton(
                  onPressed: () {
                    showDialog(
                      context: context,
                      builder: (context) => const AddPodcastDialog(),
                    );
                  },
                  child: Text(l10n.podcast_add_first),
                ),
              ],
            ),
          );
        }

        if (isMobile) {
          return ListView.builder(
            itemCount: response.subscriptions.length,
            itemBuilder: (context, index) {
              final subscription = response.subscriptions[index];
              return ListTile(
                leading: Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.primaryContainer,
                    borderRadius: BorderRadius.circular(8),
                    image: subscription.imageUrl != null
                        ? DecorationImage(
                            image: NetworkImage(subscription.imageUrl!),
                            fit: BoxFit.cover,
                          )
                        : null,
                  ),
                  child: subscription.imageUrl == null
                      ? Icon(Icons.podcasts, color: Theme.of(context).colorScheme.onPrimaryContainer)
                      : null,
                ),
                title: Text(subscription.title),
                subtitle: Text(
                  subscription.description ?? l10n.podcast_description,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                onTap: () {
                  context.push('/podcast/episodes/${subscription.id}', extra: subscription);
                },
              );
            },
          );
        }

        return GridView.builder(
          gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: screenWidth < 900 ? 2 : (screenWidth < 1200 ? 3 : 4),
            crossAxisSpacing: 16,
            mainAxisSpacing: 16,
            childAspectRatio: 0.72,
          ),
          itemCount: response.subscriptions.length,
          itemBuilder: (context, index) {
            final subscription = response.subscriptions[index];
            return Card(
              clipBehavior: Clip.antiAlias,
              child: InkWell(
                onTap: () {
                  context.push('/podcast/episodes/${subscription.id}', extra: subscription);
                },
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    AspectRatio(
                      aspectRatio: 16 / 9,
                      child: Container(
                        color: Theme.of(context).colorScheme.primaryContainer,
                        child: subscription.imageUrl != null
                            ? Image.network(
                                subscription.imageUrl!,
                                fit: BoxFit.cover,
                                errorBuilder: (context, error, stackTrace) => Icon(
                                  Icons.podcasts,
                                  size: 48,
                                  color: Theme.of(context).colorScheme.onPrimaryContainer,
                                ),
                              )
                            : Icon(
                                Icons.podcasts,
                                size: 48,
                                color: Theme.of(context).colorScheme.onPrimaryContainer,
                              ),
                      ),
                    ),
                    Expanded(
                      child: Padding(
                        padding: const EdgeInsets.all(12),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              subscription.title,
                              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                                    fontWeight: FontWeight.bold,
                                  ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            const SizedBox(height: 4),
                            Expanded(
                              child: Text(
                                subscription.description ?? l10n.podcast_description,
                                style: Theme.of(context).textTheme.bodySmall?.copyWith(
                                  color: Theme.of(context).colorScheme.onSurfaceVariant,
                                ),
                                overflow: TextOverflow.fade,
                              ),
                            ),
                            const SizedBox(height: 8),
                            Wrap(
                              spacing: 8,
                              runSpacing: 4,
                              alignment: WrapAlignment.spaceBetween,
                              crossAxisAlignment: WrapCrossAlignment.center,
                              children: [
                                Text(
                                  '${subscription.episodeCount} ${l10n.podcast_episodes}',
                                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                    color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                                    fontWeight: FontWeight.w500,
                                  ),
                                ),
                                if (subscription.lastFetchedAt != null)
                                  Text(
                                    '${l10n.podcast_updated} ${_formatDate(subscription.lastFetchedAt!)}',
                                    style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                      color: Theme.of(context).colorScheme.onSurfaceVariant.withValues(alpha: 0.7),
                                    ),
                                  ),
                              ],
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            );
          },
        );
      },
      loading: () => const Center(child: CircularProgressIndicator()),
      error: (error, stackTrace) => Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.orange),
            const SizedBox(height: 16),
            Text(l10n.podcast_failed_load_subscriptions),
            Text(error.toString(), style: Theme.of(context).textTheme.bodySmall),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: () {
                ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
              },
              icon: const Icon(Icons.refresh),
              label: Text(l10n.retry),
            ),
          ],
        ),
      ),
    );
  }

  String _formatDate(DateTime date) {
    // 确保使用本地时间，而不是 UTC 时间
    final localDate = date.isUtc ? date.toLocal() : date;
    return '${localDate.year}-${localDate.month.toString().padLeft(2, '0')}-${localDate.day.toString().padLeft(2, '0')}';
  }
}