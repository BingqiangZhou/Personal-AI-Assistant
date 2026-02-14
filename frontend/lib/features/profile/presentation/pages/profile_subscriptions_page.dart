import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:personal_ai_assistant/core/localization/app_localizations.dart';
import 'package:personal_ai_assistant/features/podcast/core/utils/episode_description_helper.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_state_models.dart';
import 'package:personal_ai_assistant/features/podcast/data/models/podcast_subscription_model.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/constants/podcast_ui_constants.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/providers/podcast_providers.dart';
import 'package:personal_ai_assistant/features/podcast/presentation/widgets/podcast_image_widget.dart';

class ProfileSubscriptionsPage extends ConsumerStatefulWidget {
  const ProfileSubscriptionsPage({super.key});

  @override
  ConsumerState<ProfileSubscriptionsPage> createState() =>
      _ProfileSubscriptionsPageState();
}

class _ProfileSubscriptionsPageState
    extends ConsumerState<ProfileSubscriptionsPage> {
  final ScrollController _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);

    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref
          .read(podcastSubscriptionProvider.notifier)
          .loadSubscriptions()
          .catchError((_) {});
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

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final state = ref.watch(podcastSubscriptionProvider);
    final subscriptions = state.subscriptions;

    return Scaffold(
      appBar: AppBar(title: Text(l10n.profile_subscriptions)),
      body: RefreshIndicator(
        onRefresh: () =>
            ref.read(podcastSubscriptionProvider.notifier).refreshSubscriptions(),
        child: _buildBody(context, l10n, state, subscriptions),
      ),
    );
  }

  Widget _buildBody(
    BuildContext context,
    AppLocalizations l10n,
    PodcastSubscriptionState state,
    List<PodcastSubscriptionModel> subscriptions,
  ) {
    if (state.isLoading && subscriptions.isEmpty) {
      return ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        children: const [
          SizedBox(height: 140),
          Center(child: CircularProgressIndicator()),
        ],
      );
    }

    if (state.error != null && subscriptions.isEmpty) {
      return ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        children: [
          const SizedBox(height: 120),
          Icon(
            Icons.error_outline,
            size: 56,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Center(
            child: Text(
              state.error.toString(),
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      );
    }

    if (subscriptions.isEmpty) {
      return ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        children: [
          const SizedBox(height: 120),
          Icon(
            Icons.subscriptions_outlined,
            size: 56,
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
          const SizedBox(height: 16),
          Center(
            child: Text(
              l10n.podcast_no_subscriptions,
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          const SizedBox(height: 8),
          Center(
            child: Text(
              l10n.feed_no_subscriptions_hint,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ),
        ],
      );
    }

    return ListView.builder(
      controller: _scrollController,
      physics: const AlwaysScrollableScrollPhysics(),
      padding: const EdgeInsets.all(16),
      itemCount: subscriptions.length + 1,
      itemBuilder: (context, index) {
        if (index == subscriptions.length) {
          return _buildLoadingIndicator(
            context,
            state.hasMore,
            state.isLoadingMore,
            state.total,
            l10n,
          );
        }

        final subscription = subscriptions[index];
        if (index == subscriptions.length - 1 &&
            state.hasMore &&
            !state.isLoadingMore) {
          WidgetsBinding.instance.addPostFrameCallback((_) {
            if (mounted) {
              ref
                  .read(podcastSubscriptionProvider.notifier)
                  .loadMoreSubscriptions();
            }
          });
        }
        return Card(
          margin: const EdgeInsets.symmetric(
            horizontal: kPodcastRowCardHorizontalMargin,
            vertical: kPodcastRowCardVerticalMargin,
          ),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(kPodcastRowCardCornerRadius),
            side: BorderSide.none,
          ),
          clipBehavior: Clip.antiAlias,
          child: InkWell(
            onTap: () {
              context.push(
                '/podcast/episodes/${subscription.id}',
                extra: subscription,
              );
            },
            borderRadius: BorderRadius.circular(kPodcastRowCardCornerRadius),
            child: SizedBox(
              key: ValueKey(
                'profile_subscription_card_content_${subscription.id}',
              ),
              height: kPodcastRowCardTargetHeight,
              child: Padding(
                padding: const EdgeInsets.symmetric(
                  horizontal: kPodcastRowCardHorizontalPadding,
                  vertical: 6,
                ),
                child: Row(
                  children: [
                    ClipRRect(
                      borderRadius: BorderRadius.circular(
                        kPodcastRowCardImageRadius,
                      ),
                      child: PodcastImageWidget(
                        imageUrl: subscription.imageUrl,
                        width: kPodcastRowCardImageSize,
                        height: kPodcastRowCardImageSize,
                        iconSize: 24,
                        iconColor: Theme.of(context).colorScheme.primary,
                      ),
                    ),
                    const SizedBox(width: kPodcastRowCardHorizontalGap),
                    Expanded(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            subscription.title,
                            style: Theme.of(context).textTheme.titleSmall
                                ?.copyWith(fontWeight: FontWeight.w700),
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
                            style: Theme.of(context).textTheme.bodySmall
                                ?.copyWith(
                                  color: Theme.of(context)
                                      .colorScheme
                                      .onSurfaceVariant,
                                ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                    Icon(
                      Icons.chevron_right,
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                      size: 22,
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildLoadingIndicator(
    BuildContext context,
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
            '${l10n.profile_subscriptions}: $total',
            style: TextStyle(color: Colors.grey[600], fontSize: 14),
          ),
        ),
      );
    }

    return const SizedBox.shrink();
  }
}
