import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:url_launcher/url_launcher.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../../../core/widgets/custom_adaptive_navigation.dart';
import '../../../../core/widgets/top_floating_notice.dart';
import '../../data/models/podcast_discover_chart_model.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/utils/podcast_url_utils.dart';
import '../constants/podcast_ui_constants.dart';
import '../providers/country_selector_provider.dart';
import '../providers/podcast_discover_provider.dart';
import '../providers/podcast_providers.dart';
import '../providers/podcast_search_provider.dart' as search;
import '../widgets/country_selector_dropdown.dart';
import '../widgets/podcast_image_widget.dart';
import '../widgets/podcast_search_result_card.dart';

class PodcastListPage extends ConsumerStatefulWidget {
  const PodcastListPage({super.key});

  @override
  ConsumerState<PodcastListPage> createState() => _PodcastListPageState();
}

class _PodcastListPageState extends ConsumerState<PodcastListPage> {
  final TextEditingController _searchController = TextEditingController();
  final FocusNode _searchFocusNode = FocusNode();
  final Set<int> _subscribingShowIds = <int>{};
  final Set<int> _subscribedShowIds = <int>{};

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(podcastSubscriptionProvider.notifier).loadSubscriptions();
      ref.read(podcastDiscoverProvider.notifier).loadInitialData();
    });
  }

  @override
  void dispose() {
    _searchController.dispose();
    _searchFocusNode.dispose();
    super.dispose();
  }

  Future<void> _openCountrySelector(BuildContext context) async {
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (sheetContext) {
        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
            child: CountrySelectorDropdown(
              onCountryChanged: (country) {
                ref
                    .read(podcastDiscoverProvider.notifier)
                    .onCountryChanged(country);
                if (ref
                    .read(search.podcastSearchProvider)
                    .currentQuery
                    .isNotEmpty) {
                  ref.read(search.podcastSearchProvider.notifier).retrySearch();
                }
                Navigator.of(sheetContext).pop();
              },
            ),
          ),
        );
      },
    );
  }

  void _onSearchChanged(String query) {
    if (query.trim().isEmpty) {
      ref.read(search.podcastSearchProvider.notifier).clearSearch();
      return;
    }
    ref.read(search.podcastSearchProvider.notifier).searchPodcasts(query);
  }

  void _clearSearch() {
    setState(() {
      _searchController.clear();
    });
    ref.read(search.podcastSearchProvider.notifier).clearSearch();
    _searchFocusNode.requestFocus();
  }

  Future<void> _handleSubscribeFromSearch(PodcastSearchResult result) async {
    final l10n = AppLocalizations.of(context)!;
    if (result.feedUrl == null || result.collectionName == null) {
      showTopFloatingNotice(
        context,
        message: l10n.podcast_subscribe_failed('Invalid podcast data'),
        isError: true,
      );
      return;
    }

    try {
      await ref
          .read(podcastSubscriptionProvider.notifier)
          .addSubscription(feedUrl: result.feedUrl!);
      if (!mounted) return;
      showTopFloatingNotice(
        context,
        message: l10n.podcast_subscribe_success(result.collectionName!),
      );
    } catch (error) {
      if (!mounted) return;
      showTopFloatingNotice(
        context,
        message: l10n.podcast_subscribe_failed(error.toString()),
        isError: true,
      );
    }
  }

  Future<void> _handleSubscribeFromChart(PodcastDiscoverItem item) async {
    final l10n = AppLocalizations.of(context)!;
    final country = ref.read(countrySelectorProvider).selectedCountry;
    final itunesId = item.itunesId;

    if (itunesId == null) {
      showTopFloatingNotice(
        context,
        message: l10n.podcast_subscribe_failed('Invalid show id'),
        isError: true,
      );
      return;
    }
    if (_subscribingShowIds.contains(itunesId)) {
      return;
    }

    setState(() {
      _subscribingShowIds.add(itunesId);
    });

    try {
      final searchService = ref.read(search.iTunesSearchServiceProvider);
      final lookup = await searchService.lookupPodcast(
        itunesId: itunesId,
        country: country,
      );
      if (lookup?.feedUrl == null) {
        throw Exception('No RSS feed url for this show');
      }

      await ref
          .read(podcastSubscriptionProvider.notifier)
          .addSubscription(feedUrl: lookup!.feedUrl!);

      if (!mounted) return;
      setState(() {
        _subscribedShowIds.add(itunesId);
      });
      showTopFloatingNotice(
        context,
        message: l10n.podcast_subscribe_success(
          lookup.collectionName ?? item.title,
        ),
      );
    } catch (error) {
      if (!mounted) return;
      showTopFloatingNotice(
        context,
        message: l10n.podcast_subscribe_failed(error.toString()),
        isError: true,
      );
    } finally {
      if (mounted) {
        setState(() {
          _subscribingShowIds.remove(itunesId);
        });
      }
    }
  }

  Future<void> _openExternalLink(String url) async {
    final l10n = AppLocalizations.of(context)!;
    final uri = Uri.tryParse(url);
    if (uri == null) {
      showTopFloatingNotice(
        context,
        message: l10n.podcast_discover_open_link_failed,
        isError: true,
      );
      return;
    }

    final opened = await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!opened && mounted) {
      showTopFloatingNotice(
        context,
        message: l10n.podcast_discover_open_link_failed,
        isError: true,
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final searchState = ref.watch(search.podcastSearchProvider);
    final discoverState = ref.watch(podcastDiscoverProvider);
    final countryState = ref.watch(countrySelectorProvider);

    return ResponsiveContainer(
      child: Material(
        color: Colors.transparent,
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
              height: 56,
              child: Row(
                children: [
                  Expanded(
                    child: Text(
                      l10n.podcast_discover_title,
                      key: const Key('podcast_discover_header_title'),
                      style: theme.textTheme.headlineMedium?.copyWith(
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ),
                  FilledButton.tonalIcon(
                    key: const Key('podcast_discover_country_button'),
                    onPressed: () => _openCountrySelector(context),
                    icon: const Icon(Icons.flag_outlined, size: 16),
                    label: Text(
                      countryState.selectedCountry.code.toUpperCase(),
                    ),
                    style: FilledButton.styleFrom(
                      visualDensity: VisualDensity.compact,
                      padding: const EdgeInsets.symmetric(
                        horizontal: 12,
                        vertical: 8,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            _buildDiscoverSearchInput(context, l10n),
            const SizedBox(height: 12),
            Expanded(
              child: searchState.hasSearched
                  ? _buildSearchResults(context, searchState, l10n)
                  : _buildDiscoverContent(context, discoverState),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDiscoverContent(
    BuildContext context,
    PodcastDiscoverState discoverState,
  ) {
    final l10n = AppLocalizations.of(context)!;

    if (discoverState.isLoading &&
        discoverState.topShows.isEmpty &&
        discoverState.topEpisodes.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }

    if (discoverState.error != null &&
        discoverState.topShows.isEmpty &&
        discoverState.topEpisodes.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 44),
            const SizedBox(height: 12),
            Text(discoverState.error!),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: () {
                ref.read(podcastDiscoverProvider.notifier).loadInitialData();
              },
              icon: const Icon(Icons.refresh),
              label: Text(l10n.retry),
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: () => ref.read(podcastDiscoverProvider.notifier).refresh(),
      child: ListView(
        key: const Key('podcast_discover_list'),
        children: [
          _buildTabSelector(context, discoverState),
          const SizedBox(height: 12),
          _buildCategorySection(context, discoverState),
          const SizedBox(height: 14),
          _buildTopChartsSection(context, discoverState),
          const SizedBox(height: 16),
        ],
      ),
    );
  }

  Widget _buildTabSelector(BuildContext context, PodcastDiscoverState state) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);

    return Container(
      key: const Key('podcast_discover_tab_selector'),
      height: 44,
      padding: const EdgeInsets.all(4),
      decoration: BoxDecoration(
        color: theme.colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
      ),
      child: Row(
        children: [
          Expanded(
            child: _buildTabItem(
              context: context,
              key: const Key('podcast_discover_tab_podcasts'),
              label: l10n.podcast_title,
              selected: state.selectedTab == PodcastDiscoverTab.podcasts,
              onTap: () => ref
                  .read(podcastDiscoverProvider.notifier)
                  .setTab(PodcastDiscoverTab.podcasts),
            ),
          ),
          const SizedBox(width: 6),
          Expanded(
            child: _buildTabItem(
              context: context,
              key: const Key('podcast_discover_tab_episodes'),
              label: l10n.podcast_episodes,
              selected: state.selectedTab == PodcastDiscoverTab.episodes,
              onTap: () => ref
                  .read(podcastDiscoverProvider.notifier)
                  .setTab(PodcastDiscoverTab.episodes),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDiscoverSearchInput(
    BuildContext context,
    AppLocalizations l10n,
  ) {
    final theme = Theme.of(context);

    return Material(
      key: const Key('podcast_discover_search_bar'),
      color: theme.colorScheme.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
        side: BorderSide(color: theme.colorScheme.outlineVariant),
      ),
      child: SizedBox(
        height: 48,
        child: Row(
          children: [
            Padding(
              padding: const EdgeInsets.only(left: 12),
              child: Icon(
                Icons.search,
                size: 20,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: TextField(
                key: const Key('podcast_discover_search_input'),
                controller: _searchController,
                focusNode: _searchFocusNode,
                textInputAction: TextInputAction.search,
                decoration: InputDecoration(
                  border: InputBorder.none,
                  enabledBorder: InputBorder.none,
                  focusedBorder: InputBorder.none,
                  disabledBorder: InputBorder.none,
                  errorBorder: InputBorder.none,
                  focusedErrorBorder: InputBorder.none,
                  hintText: l10n.podcast_discover_search_hint,
                  isDense: true,
                  contentPadding: EdgeInsets.zero,
                  hintStyle: theme.textTheme.bodyLarge?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                onChanged: (value) {
                  setState(() {});
                  _onSearchChanged(value);
                },
              ),
            ),
            if (_searchController.text.isNotEmpty)
              IconButton(
                onPressed: _clearSearch,
                icon: Icon(
                  Icons.clear,
                  size: 18,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              )
            else
              const SizedBox(width: 8),
          ],
        ),
      ),
    );
  }

  Widget _buildTabItem({
    required BuildContext context,
    required Key key,
    required String label,
    required bool selected,
    required VoidCallback onTap,
  }) {
    final theme = Theme.of(context);
    final labelStyle = theme.textTheme.titleMedium?.copyWith(
      fontWeight: selected ? FontWeight.w700 : FontWeight.w600,
      color: selected
          ? theme.colorScheme.onSurface
          : theme.colorScheme.onSurfaceVariant,
    );

    return AnimatedContainer(
      key: key,
      duration: const Duration(milliseconds: 180),
      curve: Curves.easeOutCubic,
      decoration: BoxDecoration(
        color: selected ? theme.colorScheme.surface : Colors.transparent,
        borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
      ),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
          onTap: onTap,
          child: Center(child: Text(label, style: labelStyle)),
        ),
      ),
    );
  }

  Widget _buildTopChartsSection(
    BuildContext context,
    PodcastDiscoverState state,
  ) {
    final l10n = AppLocalizations.of(context)!;
    final titleStyle = Theme.of(
      context,
    ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.bold);
    final subtitleColor = Theme.of(context).colorScheme.onSurfaceVariant;
    final notifier = ref.read(podcastDiscoverProvider.notifier);
    final countryName = _countryDisplayName(state.country, l10n);

    return Column(
      key: const Key('podcast_discover_top_charts'),
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Expanded(
              child: Text(l10n.podcast_discover_top_charts, style: titleStyle),
            ),
            if (state.canSeeAll)
              TextButton(
                key: const Key('podcast_discover_see_all'),
                onPressed: notifier.toggleSeeAll,
                child: Text(
                  state.isCurrentTabExpanded
                      ? l10n.podcast_discover_collapse
                      : l10n.podcast_discover_see_all,
                ),
              ),
          ],
        ),
        const SizedBox(height: 2),
        Text(
          l10n.podcast_discover_trending_in(countryName),
          style: TextStyle(color: subtitleColor),
        ),
        const SizedBox(height: 10),
        if (state.visibleItems.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 16),
            child: Text(l10n.podcast_discover_no_chart_data),
          )
        else
          ...state.visibleItems.asMap().entries.map((entry) {
            final rank = entry.key + 1;
            final item = entry.value;
            return _buildChartRow(context, rank, item);
          }),
      ],
    );
  }

  Widget _buildChartRow(
    BuildContext context,
    int rank,
    PodcastDiscoverItem item,
  ) {
    final theme = Theme.of(context);
    final showSubscribe = item.isPodcastShow;
    final itunesId = item.itunesId;
    final isSubscribing =
        itunesId != null && _subscribingShowIds.contains(itunesId);
    final isSubscribed =
        itunesId != null && _subscribedShowIds.contains(itunesId);

    return Padding(
      key: Key('podcast_discover_chart_row_${item.itemId}'),
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () => _openExternalLink(item.url),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 6),
          child: Row(
            children: [
              SizedBox(
                width: 24,
                child: Text(
                  '$rank',
                  style: theme.textTheme.titleMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
              const SizedBox(width: 10),
              ClipRRect(
                borderRadius: BorderRadius.circular(10),
                child: PodcastImageWidget(
                  imageUrl: item.artworkUrl,
                  width: 62,
                  height: 62,
                  iconSize: 24,
                  iconColor: theme.colorScheme.primary,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      item.title,
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.titleMedium?.copyWith(
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      item.artist,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              if (showSubscribe)
                SizedBox(
                  width: 36,
                  height: 36,
                  child: isSubscribing
                      ? const Padding(
                          padding: EdgeInsets.all(8),
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : IconButton(
                          key: Key('podcast_discover_subscribe_${item.itemId}'),
                          onPressed: isSubscribed
                              ? null
                              : () => _handleSubscribeFromChart(item),
                          icon: Icon(
                            isSubscribed
                                ? Icons.check_circle
                                : Icons.add_circle_outline,
                          ),
                        ),
                ),
              SizedBox(
                width: 36,
                height: 36,
                child: IconButton(
                  key: Key('podcast_discover_open_${item.itemId}'),
                  onPressed: () => _openExternalLink(item.url),
                  icon: const Icon(Icons.play_circle_outline),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildCategorySection(
    BuildContext context,
    PodcastDiscoverState state,
  ) {
    final l10n = AppLocalizations.of(context)!;
    final notifier = ref.read(podcastDiscoverProvider.notifier);
    final categories = state.categories;
    final theme = Theme.of(context);
    final selected = state.selectedCategory;

    final chipItems = <String>[
      PodcastDiscoverState.allCategoryValue,
      ...categories,
    ];
    final keyOccurrences = <String, int>{};

    return SingleChildScrollView(
      key: const Key('podcast_discover_category_chips'),
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          for (var index = 0; index < chipItems.length; index++) ...[
            () {
              final rawValue = chipItems[index];
              final baseKey = _normalizeCategoryKey(rawValue);
              final count = (keyOccurrences[baseKey] ?? 0) + 1;
              keyOccurrences[baseKey] = count;
              final uniqueKey = count == 1 ? baseKey : '${baseKey}_$count';

              return _buildCategoryChip(
                theme: theme,
                label: rawValue == PodcastDiscoverState.allCategoryValue
                    ? l10n.podcast_filter_all
                    : rawValue,
                selected: rawValue == PodcastDiscoverState.allCategoryValue
                    ? selected == PodcastDiscoverState.allCategoryValue
                    : selected.toLowerCase() == rawValue.toLowerCase(),
                onSelected: (_) => notifier.selectCategory(rawValue),
                keyValue: uniqueKey,
              );
            }(),
            if (index != chipItems.length - 1) const SizedBox(width: 8),
          ],
        ],
      ),
    );
  }

  Widget _buildCategoryChip({
    required ThemeData theme,
    required String label,
    required bool selected,
    required ValueChanged<bool> onSelected,
    required String keyValue,
  }) {
    return ChoiceChip(
      key: Key(
        'podcast_discover_category_chip_${_normalizeCategoryKey(keyValue)}',
      ),
      label: Text(label, maxLines: 1, overflow: TextOverflow.ellipsis),
      selected: selected,
      onSelected: onSelected,
      showCheckmark: false,
      visualDensity: const VisualDensity(horizontal: -1, vertical: -2),
      side: BorderSide(
        color: selected
            ? theme.colorScheme.primary
            : theme.colorScheme.outlineVariant,
      ),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
      labelStyle: theme.textTheme.labelLarge?.copyWith(
        fontWeight: FontWeight.w600,
        color: selected
            ? theme.colorScheme.onPrimary
            : theme.colorScheme.onSurfaceVariant,
      ),
      selectedColor: theme.colorScheme.primary,
      backgroundColor: theme.colorScheme.surfaceContainerHighest,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
    );
  }

  String _normalizeCategoryKey(String value) {
    final normalized = value.toLowerCase().replaceAll(
      RegExp(r'[^a-z0-9]+'),
      '_',
    );
    final trimmed = normalized.replaceAll(RegExp(r'^_+|_+$'), '');
    return trimmed.isEmpty ? 'category' : trimmed;
  }

  Widget _buildSearchResults(
    BuildContext context,
    search.PodcastSearchState searchState,
    AppLocalizations l10n,
  ) {
    final subscriptionState = ref.watch(podcastSubscriptionProvider);

    if (searchState.isLoading) {
      return const Center(child: CircularProgressIndicator());
    }

    if (searchState.error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.error_outline, size: 44),
            const SizedBox(height: 12),
            Text(searchState.error!, textAlign: TextAlign.center),
            const SizedBox(height: 12),
            FilledButton.icon(
              onPressed: () {
                ref.read(search.podcastSearchProvider.notifier).retrySearch();
              },
              icon: const Icon(Icons.refresh),
              label: Text(l10n.retry),
            ),
          ],
        ),
      );
    }

    if (searchState.results.isEmpty) {
      return Center(
        child: Text(
          l10n.podcast_search_no_results,
          style: Theme.of(context).textTheme.bodyLarge,
        ),
      );
    }

    return ListView.builder(
      key: const Key('podcast_discover_search_results'),
      itemCount: searchState.results.length,
      itemBuilder: (context, index) {
        final result = searchState.results[index];
        final isSubscribed = subscriptionState.subscriptions.any(
          (sub) =>
              PodcastUrlUtils.feedUrlMatches(sub.sourceUrl, result.feedUrl),
        );
        final isSubscribing =
            result.feedUrl != null &&
            subscriptionState.subscribingFeedUrls.any(
              (url) => PodcastUrlUtils.feedUrlMatches(url, result.feedUrl),
            );

        return PodcastSearchResultCard(
          result: result,
          onSubscribe: _handleSubscribeFromSearch,
          isSubscribed: isSubscribed,
          isSubscribing: isSubscribing,
          searchCountry: searchState.searchCountry,
          key: ValueKey('search_${result.feedUrl}'),
        );
      },
    );
  }

  String _countryDisplayName(PodcastCountry country, AppLocalizations l10n) {
    return switch (country.localizationKey) {
      'podcast_country_china' => l10n.podcast_country_china,
      'podcast_country_usa' => l10n.podcast_country_usa,
      'podcast_country_japan' => l10n.podcast_country_japan,
      'podcast_country_uk' => l10n.podcast_country_uk,
      'podcast_country_germany' => l10n.podcast_country_germany,
      'podcast_country_france' => l10n.podcast_country_france,
      'podcast_country_canada' => l10n.podcast_country_canada,
      'podcast_country_australia' => l10n.podcast_country_australia,
      'podcast_country_korea' => l10n.podcast_country_korea,
      'podcast_country_taiwan' => l10n.podcast_country_taiwan,
      'podcast_country_hong_kong' => l10n.podcast_country_hong_kong,
      'podcast_country_india' => l10n.podcast_country_india,
      'podcast_country_brazil' => l10n.podcast_country_brazil,
      'podcast_country_mexico' => l10n.podcast_country_mexico,
      'podcast_country_spain' => l10n.podcast_country_spain,
      'podcast_country_italy' => l10n.podcast_country_italy,
      _ => country.code.toUpperCase(),
    };
  }
}
