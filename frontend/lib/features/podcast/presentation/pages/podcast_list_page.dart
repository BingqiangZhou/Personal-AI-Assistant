import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../core/utils/episode_description_helper.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/models/podcast_subscription_model.dart';
import '../constants/podcast_ui_constants.dart';
import '../providers/bulk_selection_provider.dart';
import '../providers/podcast_providers.dart';
import '../providers/podcast_search_provider.dart' as search;
import '../widgets/add_podcast_dialog.dart';
import '../widgets/bulk_import_dialog.dart';
import '../widgets/podcast_bulk_delete_dialog.dart';
import '../widgets/search_panel.dart';

class PodcastListPage extends ConsumerStatefulWidget {
  const PodcastListPage({super.key});

  @override
  ConsumerState<PodcastListPage> createState() => _PodcastListPageState();
}

class _PodcastListPageState extends ConsumerState<PodcastListPage> {
  final ScrollController _scrollController = ScrollController();
  final GlobalKey<TooltipState> _discoverHintTooltipKey =
      GlobalKey<TooltipState>();

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);

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
    if (_scrollController.position.pixels >=
        _scrollController.position.maxScrollExtent - 200) {
      ref.read(podcastSubscriptionProvider.notifier).loadMoreSubscriptions();
    }
  }

  Future<void> _handleSubscribeFromSearch(PodcastSearchResult result) async {
    final l10n = AppLocalizations.of(context)!;
    final scaffoldMessenger = ScaffoldMessenger.of(context);

    if (result.feedUrl == null || result.collectionName == null) {
      scaffoldMessenger.showSnackBar(
        SnackBar(
          content: Text(l10n.podcast_subscribe_failed('Invalid podcast data')),
          backgroundColor: Theme.of(context).colorScheme.error,
          duration: const Duration(seconds: 3),
        ),
      );
      return;
    }

    try {
      await ref
          .read(podcastSubscriptionProvider.notifier)
          .addSubscription(feedUrl: result.feedUrl!);

      if (mounted) {
        scaffoldMessenger.showSnackBar(
          SnackBar(
            content: Text(
              l10n.podcast_subscribe_success(result.collectionName!),
            ),
            duration: const Duration(seconds: 2),
          ),
        );
      }
    } catch (error) {
      if (mounted) {
        scaffoldMessenger.showSnackBar(
          SnackBar(
            content: Text(l10n.podcast_subscribe_failed(error.toString())),
            backgroundColor: Theme.of(context).colorScheme.error,
            duration: const Duration(seconds: 3),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final bulkSelectionState = ref.watch(bulkSelectionProvider);
    final isSelectionMode = bulkSelectionState.isSelectionMode;
    final searchState = ref.watch(search.podcastSearchProvider);
    final subscriptionState = ref.watch(podcastSubscriptionProvider);
    final sectionTitleStyle = theme.textTheme.titleLarge?.copyWith(
      fontWeight: FontWeight.w700,
    );

    return ResponsiveContainer(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            height: 56,
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    isSelectionMode
                        ? l10n.podcast_bulk_select_mode
                        : l10n.podcast_title,
                    key: const Key('podcast_list_header_title'),
                    style: theme.textTheme.headlineMedium?.copyWith(
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                if (!isSelectionMode) ...[
                  IconButton(
                    key: const Key('podcast_list_action_add'),
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
                    key: const Key('podcast_list_action_bulk_import'),
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
                    icon: const Icon(Icons.playlist_add_outlined),
                    tooltip: l10n.podcast_bulk_import,
                  ),
                  IconButton(
                    key: const Key('podcast_list_action_select_mode'),
                    onPressed: () {
                      ref
                          .read(bulkSelectionProvider.notifier)
                          .toggleSelectionMode();
                    },
                    icon: const Icon(Icons.sort),
                    tooltip: l10n.podcast_enter_select_mode,
                  ),
                ] else ...[
                  IconButton(
                    onPressed: bulkSelectionState.selectedIds.isNotEmpty
                        ? () => ref
                              .read(bulkSelectionProvider.notifier)
                              .deselectAll()
                        : null,
                    icon: const Icon(Icons.deselect_outlined),
                    tooltip: l10n.podcast_deselect_all,
                  ),
                  IconButton(
                    onPressed: bulkSelectionState.selectedIds.isNotEmpty
                        ? () => _showBulkDeleteDialog(context)
                        : null,
                    icon: Icon(
                      Icons.delete_sweep_outlined,
                      color: bulkSelectionState.selectedIds.isNotEmpty
                          ? theme.colorScheme.error
                          : theme.colorScheme.onSurfaceVariant,
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
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: Text(
                  l10n.podcast_discover_new,
                  key: const Key('podcast_list_discover_title'),
                  style: sectionTitleStyle,
                ),
              ),
              Tooltip(
                key: _discoverHintTooltipKey,
                message: l10n.podcast_network_hint,
                triggerMode: TooltipTriggerMode.manual,
                preferBelow: false,
                child: IconButton(
                  key: const Key('podcast_list_discover_hint_action'),
                  onPressed: () {
                    _discoverHintTooltipKey.currentState
                        ?.ensureTooltipVisible();
                  },
                  icon: Icon(
                    Icons.info_outline,
                    size: 20,
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                  visualDensity: VisualDensity.compact,
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          SearchPanel(expanded: true, onSubscribe: _handleSubscribeFromSearch),
          if (!searchState.hasSearched) ...[
            const SizedBox(height: 18),
            RichText(
              key: const Key('podcast_list_subscriptions_title'),
              text: TextSpan(
                style: sectionTitleStyle,
                children: [
                  TextSpan(text: l10n.podcast_my_subscriptions),
                  TextSpan(
                    text: ' (${subscriptionState.total})',
                    style: sectionTitleStyle?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 10),
            Expanded(child: _buildSubscriptionContent(context)),
          ],
          if (isSelectionMode && bulkSelectionState.selectedIds.isNotEmpty)
            _buildBottomActionBar(
              context,
              l10n,
              bulkSelectionState.selectedIds.length,
            ),
        ],
      ),
    );
  }

  Widget _buildBottomActionBar(
    BuildContext context,
    AppLocalizations l10n,
    int selectedCount,
  ) {
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
              if (subscriptionState.subscriptions.isNotEmpty)
                Checkbox(
                  value: ref.read(bulkSelectionProvider).isSelectedAll,
                  onChanged: (value) {
                    if (value == true) {
                      ref
                          .read(bulkSelectionProvider.notifier)
                          .selectAll(
                            subscriptionState.subscriptions
                                .map((s) => s.id)
                                .toList(),
                          );
                    } else {
                      ref.read(bulkSelectionProvider.notifier).deselectAll();
                    }
                  },
                ),
              const SizedBox(width: 12),
              Text(
                l10n.podcast_selected_count(selectedCount),
                style: theme.textTheme.titleSmall,
              ),
              const Spacer(),
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

    if (subscriptionState.isLoading &&
        subscriptionState.subscriptions.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (subscriptionState.error != null &&
        subscriptionState.subscriptions.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 48, color: Colors.orange),
            const SizedBox(height: 16),
            Text(l10n.podcast_failed_load_subscriptions),
            Text(
              subscriptionState.error!,
              style: Theme.of(context).textTheme.bodySmall,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: () {
                ref
                    .read(podcastSubscriptionProvider.notifier)
                    .loadSubscriptions();
              },
              icon: const Icon(Icons.refresh),
              label: Text(l10n.retry),
            ),
          ],
        ),
      );
    }

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

    return RefreshIndicator(
      onRefresh: () =>
          ref.read(podcastSubscriptionProvider.notifier).refreshSubscriptions(),
      child: _buildSubscriptionList(
        context,
        subscriptionState.subscriptions,
        bulkSelectionState,
        subscriptionState.hasMore,
        subscriptionState.isLoadingMore,
        subscriptionState.total,
        l10n,
      ),
    );
  }

  Widget _buildSubscriptionList(
    BuildContext context,
    List<PodcastSubscriptionModel> subscriptions,
    BulkSelectionState bulkSelectionState,
    bool hasMore,
    bool isLoadingMore,
    int total,
    AppLocalizations l10n,
  ) {
    return ListView.builder(
      controller: _scrollController,
      itemCount: subscriptions.length + 1,
      itemBuilder: (context, index) {
        if (index == subscriptions.length) {
          return _buildLoadingIndicator(hasMore, isLoadingMore, total, l10n);
        }

        final subscription = subscriptions[index];
        final isSelected = bulkSelectionState.isSelected(subscription.id);

        return _buildSubscriptionRowCard(
          context,
          subscription,
          bulkSelectionState,
          isSelected,
          l10n,
        );
      },
    );
  }

  Widget _buildSubscriptionRowCard(
    BuildContext context,
    PodcastSubscriptionModel subscription,
    BulkSelectionState bulkSelectionState,
    bool isSelected,
    AppLocalizations l10n,
  ) {
    final theme = Theme.of(context);

    return Card(
      key: Key('podcast_subscription_mobile_card_${subscription.id}'),
      margin: const EdgeInsets.symmetric(
        horizontal: kPodcastRowCardHorizontalMargin,
        vertical: kPodcastRowCardVerticalMargin,
      ),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(kPodcastRowCardCornerRadius),
      ),
      clipBehavior: Clip.antiAlias,
      child: InkWell(
        onTap: bulkSelectionState.isSelectionMode
            ? () => ref
                  .read(bulkSelectionProvider.notifier)
                  .toggleSelection(subscription.id)
            : () {
                context.push(
                  '/podcast/episodes/${subscription.id}',
                  extra: subscription,
                );
              },
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
                    width: kPodcastRowCardImageSize,
                    height: kPodcastRowCardImageSize,
                    child: subscription.imageUrl != null
                        ? Image.network(
                            subscription.imageUrl!,
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
                        subscription.title,
                        style: theme.textTheme.titleSmall?.copyWith(
                          fontWeight: FontWeight.w700,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        subscription.description != null
                            ? EpisodeDescriptionHelper.stripHtmlTags(
                                subscription.description!,
                              )
                            : l10n.podcast_description,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                if (bulkSelectionState.isSelectionMode)
                  Padding(
                    padding: const EdgeInsets.only(left: 8),
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
          ),
        ),
      ),
    );
  }

  Widget _buildLoadingIndicator(
    bool hasMore,
    bool isLoadingMore,
    int total,
    AppLocalizations l10n,
  ) {
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
            '${l10n.podcast_my_subscriptions}: $total',
            style: TextStyle(color: Colors.grey[600], fontSize: 14),
          ),
        ),
      );
    }

    return const SizedBox.shrink();
  }

  void _showBulkDeleteDialog(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final selectedIds = ref.read(bulkSelectionProvider).selectedIds.toList();
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

            if (mounted) {
              scaffoldMessenger.showSnackBar(
                SnackBar(
                  content: Text(
                    response.failedCount > 0
                        ? l10n.podcast_bulk_delete_partial_success(
                            response.successCount,
                            response.failedCount,
                          )
                        : l10n.podcast_bulk_delete_success(
                            response.successCount,
                          ),
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
            if (mounted) {
              scaffoldMessenger.showSnackBar(
                SnackBar(
                  content: Text(
                    l10n.podcast_bulk_delete_failed(error.toString()),
                  ),
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
            ref.read(bulkSelectionProvider.notifier).clearSelection();
          }
        },
      ),
    );
  }

  void _showErrorDetailsDialog(
    BuildContext context,
    List<Map<String, dynamic>> errors,
  ) {
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
}
