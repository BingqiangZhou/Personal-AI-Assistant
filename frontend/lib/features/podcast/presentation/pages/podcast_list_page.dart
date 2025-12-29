import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../providers/podcast_providers.dart';
import '../providers/bulk_selection_provider.dart';
import '../widgets/add_podcast_dialog.dart';
import '../widgets/bulk_import_dialog.dart';
import '../widgets/podcast_bulk_delete_dialog.dart';

/// Material Design 3自适应播客列表页面
class PodcastListPage extends ConsumerStatefulWidget {
  const PodcastListPage({super.key});

  @override
  ConsumerState<PodcastListPage> createState() => _PodcastListPageState();
}

class _PodcastListPageState extends ConsumerState<PodcastListPage> {
  final ScrollController _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();

    // 添加滚动监听器
    _scrollController.addListener(_onScroll);

    // 加载初始数据
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
    });
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    // 当滚动到距离底部200像素时触发加载更多
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      ref.read(podcastSubscriptionProvider.notifier).loadMoreSubscriptions();
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final bulkSelectionState = ref.watch(bulkSelectionProvider);
    final isSelectionMode = bulkSelectionState.isSelectionMode;

    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 页面标题和操作区域
          SizedBox(
            height: 56,
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    isSelectionMode
                        ? l10n.podcast_bulk_select_mode
                        : l10n.podcast_title,
                    style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                          fontWeight: FontWeight.bold,
                        ),
                  ),
                ),
                if (!isSelectionMode) ...[
                  IconButton(
                    onPressed: () {
                      showDialog(
                        context: context,
                        builder: (context) => const AddPodcastDialog(),
                      );
                    },
                    icon: const Icon(Icons.add),
                    tooltip: l10n.podcast_add_podcast,
                  ),
                  IconButton(
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
                    icon: const Icon(Icons.playlist_add),
                    tooltip: l10n.podcast_bulk_import,
                  ),
                  IconButton(
                    onPressed: () {
                      ref.read(bulkSelectionProvider.notifier).toggleSelectionMode();
                    },
                    icon: const Icon(Icons.checklist),
                    tooltip: l10n.podcast_enter_select_mode,
                  ),
                ] else ...[
                  // Selection mode actions
                  IconButton(
                    onPressed: bulkSelectionState.selectedIds.isNotEmpty
                        ? () => ref.read(bulkSelectionProvider.notifier).deselectAll()
                        : null,
                    icon: const Icon(Icons.deselect),
                    tooltip: l10n.podcast_deselect_all,
                  ),
                  IconButton(
                    onPressed: bulkSelectionState.selectedIds.isNotEmpty
                        ? () => _showBulkDeleteDialog(context)
                        : null,
                    icon: Icon(
                      Icons.delete_sweep,
                      color: bulkSelectionState.selectedIds.isNotEmpty
                          ? Theme.of(context).colorScheme.error
                          : Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                    tooltip: l10n.delete,
                  ),
                  IconButton(
                    onPressed: () {
                      ref.read(bulkSelectionProvider.notifier).clearSelection();
                    },
                    icon: const Icon(Icons.close),
                    tooltip: l10n.cancel,
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(height: 24),

          // 订阅列表
          Expanded(
            child: _buildSubscriptionContent(context),
          ),

          // Bottom action bar for selection mode
          if (isSelectionMode && bulkSelectionState.selectedIds.isNotEmpty)
            _buildBottomActionBar(context, l10n, bulkSelectionState.selectedIds.length),
        ],
      ),
    );
  }

  Widget _buildBottomActionBar(BuildContext context, AppLocalizations l10n, int selectedCount) {
    final theme = Theme.of(context);
    final subscriptionState = ref.watch(podcastSubscriptionProvider);

    return Container(
      decoration: BoxDecoration(
        color: theme.colorScheme.surface,
        boxShadow: [
          BoxShadow(
            color: theme.shadowColor.withValues(alpha: 0.1),
            blurRadius: 8,
            offset: const Offset(0, -2),
          ),
        ],
      ),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              // Select all checkbox
              if (subscriptionState.subscriptions.isNotEmpty)
                Checkbox(
                  value: ref.read(bulkSelectionProvider).isSelectedAll,
                  onChanged: (value) {
                    if (value == true) {
                      ref.read(bulkSelectionProvider.notifier).selectAll(
                        subscriptionState.subscriptions.map((s) => s.id).toList(),
                      );
                    } else {
                      ref.read(bulkSelectionProvider.notifier).deselectAll();
                    }
                  },
                ),
              const SizedBox(width: 12),
              // Selected count text
              Text(
                l10n.podcast_selected_count(selectedCount),
                style: theme.textTheme.titleSmall,
              ),
              const Spacer(),
              // Delete button
              FilledButton.tonalIcon(
                onPressed: () => _showBulkDeleteDialog(context),
                icon: const Icon(Icons.delete),
                label: Text(l10n.delete),
                style: FilledButton.styleFrom(
                  foregroundColor: theme.colorScheme.error,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSubscriptionContent(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final subscriptionState = ref.watch(podcastSubscriptionProvider);
    final bulkSelectionState = ref.watch(bulkSelectionProvider);
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 600;

    // 显示初始加载状态
    if (subscriptionState.isLoading && subscriptionState.subscriptions.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    // 显示错误状态
    if (subscriptionState.error != null && subscriptionState.subscriptions.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.orange),
            const SizedBox(height: 16),
            Text(l10n.podcast_failed_load_subscriptions),
            Text(subscriptionState.error!,
                style: Theme.of(context).textTheme.bodySmall),
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
      );
    }

    // 显示空状态
    if (subscriptionState.subscriptions.isEmpty) {
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

    // 使用 RefreshIndicator 支持下拉刷新
    return RefreshIndicator(
      onRefresh: () =>
          ref.read(podcastSubscriptionProvider.notifier).refreshSubscriptions(),
      child: isMobile
          ? _buildMobileList(
              context,
              subscriptionState.subscriptions,
              bulkSelectionState,
              subscriptionState.hasMore,
              subscriptionState.isLoadingMore,
              subscriptionState.total,
              l10n,
            )
          : _buildDesktopGrid(
              context,
              subscriptionState.subscriptions,
              bulkSelectionState,
              subscriptionState.hasMore,
              subscriptionState.isLoadingMore,
              subscriptionState.total,
              l10n,
              screenWidth,
            ),
    );
  }

  Widget _buildMobileList(
    BuildContext context,
    List<PodcastSubscriptionModel> subscriptions,
    dynamic bulkSelectionState,
    bool hasMore,
    bool isLoadingMore,
    int total,
    AppLocalizations l10n,
  ) {
    return ListView.builder(
      controller: _scrollController,
      itemCount: subscriptions.length + 1, // +1 for loading indicator
      itemBuilder: (context, index) {
        if (index == subscriptions.length) {
          return _buildLoadingIndicator(hasMore, isLoadingMore, total, l10n);
        }

        final subscription = subscriptions[index];
        final isSelected = bulkSelectionState.isSelected(subscription.id);

        return ListTile(
          leading: Stack(
            children: [
              Container(
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
                    ? Icon(Icons.podcasts,
                        color: Theme.of(context).colorScheme.onPrimaryContainer)
                    : null,
              ),
              if (bulkSelectionState.isSelectionMode)
                Positioned(
                  top: 0,
                  left: 0,
                  child: Checkbox(
                    value: isSelected,
                    onChanged: (_) {
                      ref
                          .read(bulkSelectionProvider.notifier)
                          .toggleSelection(subscription.id);
                    },
                  ),
                ),
            ],
          ),
          title: Text(subscription.title),
          subtitle: Text(
            subscription.description ?? l10n.podcast_description,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
          onTap: bulkSelectionState.isSelectionMode
              ? () => ref
                  .read(bulkSelectionProvider.notifier)
                  .toggleSelection(subscription.id)
              : () {
                  context.push('/podcast/episodes/${subscription.id}',
                      extra: subscription);
                },
        );
      },
    );
  }

  Widget _buildDesktopGrid(
    BuildContext context,
    List<PodcastSubscriptionModel> subscriptions,
    dynamic bulkSelectionState,
    bool hasMore,
    bool isLoadingMore,
    int total,
    AppLocalizations l10n,
    double screenWidth,
  ) {
    return GridView.builder(
      controller: _scrollController,
      gridDelegate: SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: screenWidth < 900 ? 2 : (screenWidth < 1200 ? 3 : 4),
        crossAxisSpacing: 8,
        mainAxisSpacing: 8,
        childAspectRatio: 0.72,
      ),
      itemCount: subscriptions.length + 1, // +1 for loading indicator
      itemBuilder: (context, index) {
        if (index == subscriptions.length) {
          return _buildLoadingIndicator(hasMore, isLoadingMore, total, l10n);
        }

        final subscription = subscriptions[index];
        final isSelected = bulkSelectionState.isSelected(subscription.id);

        return Stack(
          children: [
            Card(
              clipBehavior: Clip.antiAlias,
              child: InkWell(
                onTap: bulkSelectionState.isSelectionMode
                    ? () => ref
                        .read(bulkSelectionProvider.notifier)
                        .toggleSelection(subscription.id)
                    : () {
                        context.push('/podcast/episodes/${subscription.id}',
                            extra: subscription);
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
                                errorBuilder: (context, error, stackTrace) =>
                                    Icon(
                                  Icons.podcasts,
                                  size: 48,
                                  color: Theme.of(context)
                                      .colorScheme
                                      .onPrimaryContainer,
                                ),
                              )
                            : Icon(
                                Icons.podcasts,
                                size: 48,
                                color: Theme.of(context)
                                    .colorScheme
                                    .onPrimaryContainer,
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
                              style: Theme.of(context)
                                  .textTheme
                                  .titleMedium
                                  ?.copyWith(
                                    fontWeight: FontWeight.bold,
                                  ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            const SizedBox(height: 4),
                            Expanded(
                              child: Text(
                                subscription.description ??
                                    l10n.podcast_description,
                                style: Theme.of(context)
                                    .textTheme
                                    .bodySmall
                                    ?.copyWith(
                                      color: Theme.of(context)
                                          .colorScheme
                                          .onSurfaceVariant,
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
                                  style: Theme.of(context)
                                      .textTheme
                                      .labelSmall
                                      ?.copyWith(
                                        color: Theme.of(context)
                                            .colorScheme
                                            .onSurfaceVariant
                                            .withValues(alpha: 0.7),
                                        fontWeight: FontWeight.w500,
                                      ),
                                ),
                                if (subscription.lastFetchedAt != null)
                                  Text(
                                    '${l10n.podcast_updated} ${_formatDate(subscription.lastFetchedAt!)}',
                                    style: Theme.of(context)
                                        .textTheme
                                        .labelSmall
                                        ?.copyWith(
                                          color: Theme.of(context)
                                              .colorScheme
                                              .onSurfaceVariant
                                              .withValues(alpha: 0.7),
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
            ),
            // Checkbox overlay in selection mode
            if (bulkSelectionState.isSelectionMode)
              Positioned(
                top: 8,
                left: 8,
                child: Container(
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surface,
                    borderRadius: BorderRadius.circular(4),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withValues(alpha: 0.3),
                        blurRadius: 4,
                      ),
                    ],
                  ),
                  child: Checkbox(
                    value: isSelected,
                    onChanged: (_) {
                      ref
                          .read(bulkSelectionProvider.notifier)
                          .toggleSelection(subscription.id);
                    },
                  ),
                ),
              ),
            // Selection indicator (use IgnorePointer to allow clicks to pass through)
            if (isSelected)
              Positioned.fill(
                child: IgnorePointer(
                  child: Container(
                    decoration: BoxDecoration(
                      color: Theme.of(context)
                          .colorScheme
                          .primary
                          .withValues(alpha: 0.1),
                      border: Border.all(
                        color: Theme.of(context).colorScheme.primary,
                        width: 2,
                      ),
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                ),
              ),
          ],
        );
      },
    );
  }

  Widget _buildLoadingIndicator(
      bool hasMore, bool isLoadingMore, int total, AppLocalizations l10n) {
    if (isLoadingMore) {
      return const Padding(
        padding: EdgeInsets.all(16),
        child: Center(child: CircularProgressIndicator()),
      );
    }

    if (!hasMore) {
      return Padding(
        padding: const EdgeInsets.all(16),
        child: Center(
          child: Text(
            '已加载全部 $total 个订阅',
            style: TextStyle(
              color: Colors.grey[600],
              fontSize: 14,
            ),
          ),
        ),
      );
    }

    return const SizedBox.shrink();
  }

  void _showBulkDeleteDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final selectedIds = ref.read(bulkSelectionProvider).selectedIds.toList();

    // Save ScaffoldMessenger before showing dialog to avoid using deactivated context
    final scaffoldMessenger = ScaffoldMessenger.of(context);
    final theme = Theme.of(context);

    showDialog(
      context: context,
      builder: (dialogContext) => PodcastBulkDeleteDialog(
        subscriptionIds: selectedIds,
        count: selectedIds.length,
        onDelete: () async {
          final notifier = ref.read(podcastSubscriptionProvider.notifier);
          try {
            final response = await notifier.bulkDeleteSubscriptions(
              subscriptionIds: selectedIds,
            );

            // Show success message using saved ScaffoldMessenger
            if (mounted) {
              scaffoldMessenger.showSnackBar(
                SnackBar(
                  content: Text(
                    response.failedCount > 0
                        ? l10n.podcast_bulk_delete_partial_success(
                              response.successCount,
                              response.failedCount,
                            )
                        : l10n.podcast_bulk_delete_success(response.successCount),
                  ),
                  backgroundColor: response.failedCount > 0
                      ? theme.colorScheme.surfaceContainerHighest
                      : theme.colorScheme.primary,
                  duration: const Duration(seconds: 3),
                  action: response.failedCount > 0
                      ? SnackBarAction(
                          label: l10n.podcast_view_errors,
                          textColor: theme.colorScheme.error,
                          onPressed: () {
                            _showErrorDetailsDialog(context, response.errors);
                          },
                        )
                      : null,
                ),
              );
            }
          } catch (error) {
            // Show error message using saved ScaffoldMessenger
            if (mounted) {
              scaffoldMessenger.showSnackBar(
                SnackBar(
                  content: Text(l10n.podcast_bulk_delete_failed(error.toString())),
                  backgroundColor: theme.colorScheme.error,
                  duration: const Duration(seconds: 3),
                  action: SnackBarAction(
                    label: l10n.dismiss,
                    textColor: theme.colorScheme.onError,
                    onPressed: () {},
                  ),
                ),
              );
            }
          } finally {
            // Clear selection after deletion attempt
            ref.read(bulkSelectionProvider.notifier).clearSelection();
          }
        },
      ),
    );
  }

  void _showErrorDetailsDialog(BuildContext context, List<Map<String, dynamic>> errors) {
    final l10n = AppLocalizations.of(context)!;
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(l10n.podcast_bulk_delete_errors_title),
        content: SizedBox(
          width: double.maxFinite,
          child: ListView.builder(
            shrinkWrap: true,
            itemCount: errors.length,
            itemBuilder: (context, index) {
              final error = errors[index];
              return ListTile(
                leading: const Icon(Icons.error, color: Colors.red),
                title: Text('ID: ${error['subscription_id']}'),
                subtitle: Text(error['error'].toString()),
              );
            },
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: Text(l10n.close),
          ),
        ],
      ),
    );
  }

  String _formatDate(DateTime date) {
    // 确保使用本地时间，而不是 UTC 时间
    final localDate = date.isUtc ? date.toLocal() : date;
    return '${localDate.year}-${localDate.month.toString().padLeft(2, '0')}-${localDate.day.toString().padLeft(2, '0')}';
  }
}
