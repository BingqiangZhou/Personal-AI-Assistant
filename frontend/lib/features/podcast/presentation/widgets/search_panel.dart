import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/models/podcast_state_models.dart';
import '../providers/podcast_search_provider.dart';
import '../providers/podcast_providers.dart' as providers;
import '../providers/country_selector_provider.dart';
import 'podcast_search_result_card.dart';

/// 播客搜索面板组件
///
/// Material 3 设计规范，支持展开/收起动画
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
        // 展开后自动聚焦搜索框
        WidgetsBinding.instance.addPostFrameCallback((_) {
          _focusNode.requestFocus();
        });
      } else {
        _animationController.reverse();
        // 收起时清除搜索 - 延迟到 widget tree 构建完成后
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
    _animationController.dispose();
    _searchController.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  void _handleSearch(String query) {
    ref.read(podcastSearchProvider.notifier).searchPodcasts(query);
  }

  void _handleClearSearch() {
    _searchController.clear();
    ref.read(podcastSearchProvider.notifier).clearSearch();
    _focusNode.requestFocus();
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final searchState = ref.watch(podcastSearchProvider);
    final subscriptionState = ref.watch(providers.podcastSubscriptionProvider);
    final countryState = ref.watch(countrySelectorProvider);
    final countryNotifier = ref.read(countrySelectorProvider.notifier);

    // 未展开时不显示任何内容
    if (!widget.expanded && !searchState.hasSearched) {
      return const SizedBox.shrink();
    }

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // 搜索栏和操作区域（展开时显示）
        SizeTransition(
          sizeFactor: _expandAnimation,
          axisAlignment: -1,
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 300),
            curve: Curves.easeInOut,
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerHighest,
              borderRadius: BorderRadius.circular(12),
            ),
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // 搜索输入栏（国家选择器集成在内部）
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: SearchBar(
                    controller: _searchController,
                    focusNode: _focusNode,
                    hintText: l10n.podcast_search_hint,
                    hintStyle: WidgetStateProperty.all(
                      TextStyle(
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                    ),
                    constraints: const BoxConstraints(
                      minWidth: double.infinity,
                      maxWidth: double.infinity,
                    ),
                    // 国家选择器作为前置widget（显示国家代码）
                    leading: PopupMenuButton<PodcastCountry>(
                      icon: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                        decoration: BoxDecoration(
                          color: Theme.of(context).colorScheme.primaryContainer,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              countryState.selectedCountry.code.toUpperCase(),
                              style: TextStyle(
                                fontSize: 14,
                                fontWeight: FontWeight.bold,
                                color: Theme.of(context).colorScheme.onPrimaryContainer,
                              ),
                            ),
                            const SizedBox(width: 4),
                            Icon(
                              Icons.arrow_drop_down,
                              size: 18,
                              color: Theme.of(context).colorScheme.onPrimaryContainer,
                            ),
                          ],
                        ),
                      ),
                      tooltip: l10n.podcast_country_label,
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      elevation: 8,
                      onSelected: (country) {
                        countryNotifier.selectCountry(country);
                        // 国家变化时重新搜索
                        if (_searchController.text.isNotEmpty) {
                          _handleSearch(_searchController.text);
                        }
                      },
                      itemBuilder: (context) {
                        return PodcastCountry.values.map((country) {
                          final isSelected = countryState.selectedCountry == country;
                          // 根据本地化键获取国家名称
                          String countryName;
                          switch (country.localizationKey) {
                            case 'podcast_country_china':
                              countryName = l10n.podcast_country_china;
                              break;
                            case 'podcast_country_usa':
                              countryName = l10n.podcast_country_usa;
                              break;
                            case 'podcast_country_japan':
                              countryName = l10n.podcast_country_japan;
                              break;
                            case 'podcast_country_uk':
                              countryName = l10n.podcast_country_uk;
                              break;
                            case 'podcast_country_germany':
                              countryName = l10n.podcast_country_germany;
                              break;
                            case 'podcast_country_france':
                              countryName = l10n.podcast_country_france;
                              break;
                            case 'podcast_country_canada':
                              countryName = l10n.podcast_country_canada;
                              break;
                            case 'podcast_country_australia':
                              countryName = l10n.podcast_country_australia;
                              break;
                            case 'podcast_country_korea':
                              countryName = l10n.podcast_country_korea;
                              break;
                            case 'podcast_country_taiwan':
                              countryName = l10n.podcast_country_taiwan;
                              break;
                            case 'podcast_country_hong_kong':
                              countryName = l10n.podcast_country_hong_kong;
                              break;
                            case 'podcast_country_india':
                              countryName = l10n.podcast_country_india;
                              break;
                            case 'podcast_country_brazil':
                              countryName = l10n.podcast_country_brazil;
                              break;
                            case 'podcast_country_mexico':
                              countryName = l10n.podcast_country_mexico;
                              break;
                            case 'podcast_country_spain':
                              countryName = l10n.podcast_country_spain;
                              break;
                            case 'podcast_country_italy':
                              countryName = l10n.podcast_country_italy;
                              break;
                            default:
                              countryName = country.code.toUpperCase();
                          }

                          return PopupMenuItem(
                            value: country,
                            child: Container(
                              decoration: BoxDecoration(
                                color: isSelected
                                    ? Theme.of(context).colorScheme.primaryContainer.withOpacity(0.3)
                                    : null,
                                borderRadius: BorderRadius.circular(8),
                              ),
                              padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 12),
                              child: Row(
                                children: [
                                  // 国家代码文字
                                  SizedBox(
                                    width: 32,
                                    child: Text(
                                      country.code.toUpperCase(),
                                      style: TextStyle(
                                        fontSize: 14,
                                        fontWeight: FontWeight.bold,
                                        color: Theme.of(context).colorScheme.primary,
                                      ),
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  Expanded(
                                    child: Text(
                                      countryName,
                                      style: TextStyle(
                                        fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                                      ),
                                    ),
                                  ),
                                  if (isSelected)
                                    Icon(
                                      Icons.check_circle,
                                      size: 20,
                                      color: Theme.of(context).colorScheme.primary,
                                    ),
                                ],
                              ),
                            ),
                          );
                        }).toList();
                      },
                    ),
                    trailing: [
                      if (_searchController.text.isNotEmpty)
                        IconButton(
                          icon: const Icon(Icons.clear),
                          onPressed: _handleClearSearch,
                        ),
                    ],
                    onChanged: _handleSearch,
                    elevation: WidgetStateProperty.all(0),
                    backgroundColor: WidgetStateProperty.all(
                      Theme.of(context).colorScheme.surface,
                    ),
                    padding: WidgetStateProperty.all(
                      const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    ),
                  ),
                ),

                // 网络提示
                Padding(
                  padding: const EdgeInsets.fromLTRB(16, 8, 16, 0),
                  child: Row(
                    children: [
                      Icon(
                        Icons.info_outline,
                        size: 12,
                        color: Theme.of(context).colorScheme.onSurfaceVariant,
                      ),
                      const SizedBox(width: 4),
                      Expanded(
                        child: Text(
                          l10n.podcast_network_hint,
                          style: Theme.of(context).textTheme.labelSmall?.copyWith(
                                color: Theme.of(context).colorScheme.onSurfaceVariant,
                              ),
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),

        // 搜索结果（仅在有搜索时显示）
        if (searchState.hasSearched)
          SizeTransition(
            sizeFactor: _expandAnimation,
            axisAlignment: -1,
            child: _buildSearchResults(context, searchState, subscriptionState, l10n),
          ),
      ],
    );
  }

  Widget _buildSearchResults(
    BuildContext context,
    PodcastSearchState searchState,
    PodcastSubscriptionState subscriptionState,
    AppLocalizations l10n,
  ) {
    // 加载中
    if (searchState.isLoading) {
      return SizedBox(
        height: 200,
        child: Center(
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
        ),
      );
    }

    // 错误状态
    if (searchState.error != null) {
      return SizedBox(
        height: 200,
        child: Center(
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
        ),
      );
    }

    // 无结果
    if (searchState.results.isEmpty) {
      return SizedBox(
        height: 200,
        child: Center(
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
        ),
      );
    }

    // 显示搜索结果
    return Container(
      constraints: const BoxConstraints(maxHeight: 400),
      child: ListView.builder(
        shrinkWrap: true,
        itemCount: searchState.results.length,
        itemBuilder: (context, index) {
          final result = searchState.results[index];
          // 检查该播客是否已订阅（通过 feedUrl 匹配 sourceUrl）
          final isSubscribed = subscriptionState.subscriptions.any(
            (sub) => sub.sourceUrl == result.feedUrl,
          );
          return PodcastSearchResultCard(
            result: result,
            onSubscribe: widget.onSubscribe,
            isSubscribed: isSubscribed,
            searchCountry: searchState.searchCountry,
          );
        },
      ),
    );
  }
}
