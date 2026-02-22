import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/utils/podcast_url_utils.dart';
import '../constants/podcast_ui_constants.dart';
import '../providers/country_selector_provider.dart';
import '../providers/podcast_search_provider.dart';
import '../providers/podcast_subscription_selectors.dart';
import 'country_selector_dropdown.dart';
import 'podcast_episode_search_result_card.dart';
import 'podcast_search_result_card.dart';

class SearchPanel extends ConsumerStatefulWidget {
  const SearchPanel({
    super.key,
    this.expanded = false,
    this.onExpandChanged,
    this.onSubscribe,
  });

  final bool expanded;
  final ValueChanged<bool>? onExpandChanged;
  final ValueChanged<PodcastSearchResult>? onSubscribe;

  @override
  ConsumerState<SearchPanel> createState() => _SearchPanelState();
}

class _SearchPanelState extends ConsumerState<SearchPanel>
    with SingleTickerProviderStateMixin {
  late AnimationController _animationController;
  late Animation<double> _expandAnimation;
  final TextEditingController _searchController = TextEditingController();
  final FocusNode _focusNode = FocusNode();
  final GlobalKey _countryButtonKey = GlobalKey();
  OverlayEntry? _countrySelectorOverlay;

  @override
  void initState() {
    super.initState();

    _animationController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );

    _expandAnimation = CurvedAnimation(
      parent: _animationController,
      curve: Curves.easeInOut,
    );

    if (widget.expanded) {
      _animationController.value = 1.0;
    }
  }

  @override
  void didUpdateWidget(SearchPanel oldWidget) {
    super.didUpdateWidget(oldWidget);

    if (widget.expanded != oldWidget.expanded) {
      if (widget.expanded) {
        _animationController.forward();
        WidgetsBinding.instance.addPostFrameCallback((_) {
          _focusNode.requestFocus();
        });
      } else {
        _animationController.reverse();
        WidgetsBinding.instance.addPostFrameCallback((_) {
          ref.read(podcastSearchProvider.notifier).clearSearch();
        });
        _searchController.clear();
        _focusNode.unfocus();
      }
    }
  }

  @override
  void dispose() {
    _countrySelectorOverlay?.remove();
    _animationController.dispose();
    _searchController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _toggleCountrySelector() {
    if (_countrySelectorOverlay == null) {
      _showCountrySelector();
    } else {
      _hideCountrySelector();
    }
  }

  void _showCountrySelector() {
    _hideCountrySelector();
    final renderBox =
        _countryButtonKey.currentContext?.findRenderObject() as RenderBox?;
    if (renderBox == null) {
      return;
    }

    final offset = renderBox.localToGlobal(Offset.zero);
    final size = renderBox.size;

    _countrySelectorOverlay = OverlayEntry(
      builder: (context) => _CountrySelectorOverlay(
        buttonOffset: offset,
        buttonSize: size,
        onCountryChanged: (country) {
          final countryNotifier = ref.read(countrySelectorProvider.notifier);
          countryNotifier.selectCountry(country);
          _hideCountrySelector();
          if (_searchController.text.isNotEmpty) {
            _handleSearch(_searchController.text);
          }
        },
        onDismiss: _hideCountrySelector,
      ),
    );

    Overlay.of(context).insert(_countrySelectorOverlay!);
  }

  void _hideCountrySelector() {
    _countrySelectorOverlay?.remove();
    _countrySelectorOverlay = null;
  }

  void _handleSearch(String query) {
    final notifier = ref.read(podcastSearchProvider.notifier);
    final mode = ref.read(podcastSearchProvider).searchMode;
    if (mode == PodcastSearchMode.episodes) {
      notifier.searchEpisodes(query);
      return;
    }
    notifier.searchPodcasts(query);
  }

  void _handleClearSearch() {
    _searchController.clear();
    ref.read(podcastSearchProvider.notifier).clearSearch();
    _focusNode.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final theme = Theme.of(context);
    final searchState = ref.watch(podcastSearchProvider);
    final subscribedFeedUrls = ref.watch(subscribedNormalizedFeedUrlsProvider);
    final subscribingFeedUrls = ref.watch(
      subscribingNormalizedFeedUrlsProvider,
    );
    final selectedCountry = ref.watch(
      countrySelectorProvider.select((state) => state.selectedCountry),
    );

    if (!widget.expanded && !searchState.hasSearched) {
      return const SizedBox.shrink();
    }

    Widget buildSearchBar() {
      return SizeTransition(
        sizeFactor: _expandAnimation,
        axisAlignment: -1,
        child: SearchBar(
          key: const Key('podcast_list_discover_card'),
          controller: _searchController,
          focusNode: _focusNode,
          hintText: l10n.podcast_search_hint,
          hintStyle: WidgetStateProperty.all(
            TextStyle(color: theme.colorScheme.onSurfaceVariant),
          ),
          constraints: const BoxConstraints(
            minWidth: double.infinity,
            maxWidth: double.infinity,
            minHeight: 42,
            maxHeight: 42,
          ),
          shape: WidgetStateProperty.all(
            RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
              side: BorderSide(
                color: theme.colorScheme.outlineVariant.withValues(alpha: 0.65),
              ),
            ),
          ),
          leading: InkWell(
            key: _countryButtonKey,
            onTap: _toggleCountrySelector,
            child: Container(
              key: const Key('podcast_list_discover_country_button_container'),
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              margin: const EdgeInsets.only(right: 8),
              decoration: BoxDecoration(
                color: theme.colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    selectedCountry.code.toUpperCase(),
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      color: theme.colorScheme.onPrimaryContainer,
                    ),
                  ),
                  const SizedBox(width: 4),
                  Icon(
                    _countrySelectorOverlay != null
                        ? Icons.arrow_drop_up
                        : Icons.arrow_drop_down,
                    size: 18,
                    color: theme.colorScheme.onPrimaryContainer,
                  ),
                ],
              ),
            ),
          ),
          trailing: [
            if (_searchController.text.isNotEmpty)
              Center(
                child: IconButton(
                  icon: const Icon(Icons.clear),
                  onPressed: _handleClearSearch,
                  iconSize: 18,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(),
                ),
              ),
          ],
          onChanged: _handleSearch,
          elevation: WidgetStateProperty.all(0),
          backgroundColor: WidgetStateProperty.all(theme.colorScheme.surface),
          padding: WidgetStateProperty.all(
            const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          ),
        ),
      );
    }

    if (searchState.hasSearched) {
      return Expanded(
        child: Column(
          children: [
            _buildSearchTypeSelector(context, searchState, l10n),
            const SizedBox(height: 8),
            buildSearchBar(),
            const SizedBox(height: 8),
            Expanded(
              child: _buildSearchResults(
                context,
                searchState,
                subscribedFeedUrls: subscribedFeedUrls,
                subscribingFeedUrls: subscribingFeedUrls,
                l10n: l10n,
              ),
            ),
          ],
        ),
      );
    }

    return buildSearchBar();
  }

  Widget _buildSearchTypeSelector(
    BuildContext context,
    PodcastSearchState state,
    AppLocalizations l10n,
  ) {
    final theme = Theme.of(context);
    return Align(
      alignment: Alignment.centerLeft,
      child: SegmentedButton<PodcastSearchMode>(
        key: const Key('podcast_search_type_selector'),
        segments: [
          ButtonSegment(
            value: PodcastSearchMode.podcasts,
            label: Text(l10n.podcast_search_section_podcasts),
            icon: const Icon(Icons.podcasts_outlined, size: 18),
          ),
          ButtonSegment(
            value: PodcastSearchMode.episodes,
            label: Text(l10n.podcast_search_section_episodes),
            icon: const Icon(Icons.headphones_outlined, size: 18),
          ),
        ],
        selected: {state.searchMode},
        style: SegmentedButton.styleFrom(
          backgroundColor: theme.colorScheme.surface,
          foregroundColor: theme.colorScheme.onSurfaceVariant,
          selectedForegroundColor: theme.colorScheme.onPrimary,
          selectedBackgroundColor: theme.colorScheme.primary,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        ),
        onSelectionChanged: (selection) {
          final mode = selection.first;
          ref.read(podcastSearchProvider.notifier).setSearchMode(mode);
        },
      ),
    );
  }

  Widget _buildSearchResults(
    BuildContext context,
    PodcastSearchState searchState, {
    required Set<String> subscribedFeedUrls,
    required Set<String> subscribingFeedUrls,
    required AppLocalizations l10n,
  }) {
    if (searchState.isLoading) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const CircularProgressIndicator(),
            const SizedBox(height: 16),
            Text(
              l10n.podcast_search_loading,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      );
    }

    if (searchState.error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              size: 48,
              color: Theme.of(context).colorScheme.error,
            ),
            const SizedBox(height: 16),
            Text(
              l10n.podcast_search_error,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.error,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              searchState.error!,
              style: Theme.of(context).textTheme.bodySmall,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            FilledButton.icon(
              onPressed: () {
                ref.read(podcastSearchProvider.notifier).retrySearch();
              },
              icon: const Icon(Icons.refresh),
              label: Text(l10n.retry),
            ),
          ],
        ),
      );
    }

    final resultsEmpty = searchState.searchMode == PodcastSearchMode.episodes
        ? searchState.episodeResults.isEmpty
        : searchState.podcastResults.isEmpty;
    if (resultsEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.search_off,
              size: 48,
              color: Theme.of(context).colorScheme.outlineVariant,
            ),
            const SizedBox(height: 16),
            Text(
              l10n.podcast_search_no_results,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      );
    }

    if (searchState.searchMode == PodcastSearchMode.episodes) {
      return ListView.builder(
        itemCount: searchState.episodeResults.length,
        itemBuilder: (context, index) {
          final episode = searchState.episodeResults[index];
          return PodcastEpisodeSearchResultCard(
            episode: episode,
            key: ValueKey('episode_search_${episode.trackId}'),
          );
        },
      );
    }

    final normalizedSubscribingFeedUrls = subscribingFeedUrls;

    return ListView.builder(
      itemCount: searchState.podcastResults.length,
      itemBuilder: (context, index) {
        final result = searchState.podcastResults[index];
        final normalizedResultFeedUrl = result.feedUrl == null
            ? null
            : PodcastUrlUtils.normalizeFeedUrl(result.feedUrl!);
        final isSubscribed =
            normalizedResultFeedUrl != null &&
            subscribedFeedUrls.contains(normalizedResultFeedUrl);
        final isSubscribing =
            normalizedResultFeedUrl != null &&
            normalizedSubscribingFeedUrls.contains(normalizedResultFeedUrl);

        return PodcastSearchResultCard(
          result: result,
          onSubscribe: widget.onSubscribe,
          isSubscribed: isSubscribed,
          isSubscribing: isSubscribing,
          searchCountry: searchState.searchCountry,
          key: ValueKey('search_${result.feedUrl}'),
        );
      },
    );
  }
}

class _CountrySelectorOverlay extends StatelessWidget {
  const _CountrySelectorOverlay({
    required this.buttonOffset,
    required this.buttonSize,
    required this.onCountryChanged,
    required this.onDismiss,
  });

  final Offset buttonOffset;
  final Size buttonSize;
  final ValueChanged<PodcastCountry> onCountryChanged;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final maxHeight = MediaQuery.of(context).size.height * 0.6;

    final searchBarWidth = screenWidth - 32;
    final selectorWidth = searchBarWidth.clamp(200.0, 360.0);

    final searchBarLeft = buttonOffset.dx - 6.0;
    double left = searchBarLeft;
    final double top = buttonOffset.dy + buttonSize.height + 8;

    if (left + selectorWidth > screenWidth - 8) {
      left = screenWidth - selectorWidth - 8;
    }
    if (left < 8) {
      left = 8;
    }

    return GestureDetector(
      onTap: onDismiss,
      behavior: HitTestBehavior.translucent,
      child: Stack(
        children: [
          Container(color: Colors.transparent),
          Positioned(
            left: left,
            top: top,
            child: GestureDetector(
              onTap: () {},
              child: Material(
                elevation: 8,
                borderRadius: BorderRadius.circular(12),
                child: ConstrainedBox(
                  constraints: BoxConstraints(
                    maxWidth: selectorWidth,
                    maxHeight: maxHeight,
                  ),
                  child: CountrySelectorDropdown(
                    onCountryChanged: onCountryChanged,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
