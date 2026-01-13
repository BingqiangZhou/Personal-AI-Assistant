import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';
import '../../data/models/podcast_state_models.dart';
import '../../data/utils/podcast_url_utils.dart';
import '../providers/podcast_search_provider.dart';
import '../providers/podcast_providers.dart' as providers;
import '../providers/country_selector_provider.dart';
import 'podcast_search_result_card.dart';
import 'country_selector_dropdown.dart';

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
    _hideCountrySelector(); // 先关闭已存在的

    final renderBox = _countryButtonKey.currentContext?.findRenderObject() as RenderBox?;
    if (renderBox == null) return;

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
          // 国家变化时重新搜索
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

    // 未展开时不显示任何内容
    if (!widget.expanded && !searchState.hasSearched) {
      return const SizedBox.shrink();
    }

    // 构建搜索栏UI（提取为可复用的方法）
    Widget buildSearchBar() => SizeTransition(
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
                  minHeight: 40,
                  maxHeight: 40,
                ),
                // 国家选择器作为前置widget（显示国家代码）
                leading: InkWell(
                  key: _countryButtonKey,
                  onTap: _toggleCountrySelector,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                    margin: const EdgeInsets.only(right: 8),
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
                          _countrySelectorOverlay != null ? Icons.arrow_drop_up : Icons.arrow_drop_down,
                          size: 18,
                          color: Theme.of(context).colorScheme.onPrimaryContainer,
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
    );

    // 如果有搜索结果，使用 Expanded 占满剩余空间
    if (searchState.hasSearched) {
      return Expanded(
        child: Column(
          children: [
            buildSearchBar(),
            const SizedBox(height: 8),
            Expanded(
              child: _buildSearchResults(context, searchState, subscriptionState, l10n),
            ),
          ],
        ),
      );
    }

    // 没有搜索结果时，只显示搜索栏
    return buildSearchBar();
  }

  Widget _buildSearchResults(
    BuildContext context,
    PodcastSearchState searchState,
    PodcastSubscriptionState subscriptionState,
    AppLocalizations l10n,
  ) {
    // 加载中
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

    // 错误状态
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

    // 无结果
    if (searchState.results.isEmpty) {
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

    // 显示搜索结果
    return ListView.builder(
      itemCount: searchState.results.length,
      itemBuilder: (context, index) {
        final result = searchState.results[index];
        // 检查该播客是否已订阅（使用规范化 URL 比较）
        final isSubscribed = subscriptionState.subscriptions.any(
          (sub) => PodcastUrlUtils.feedUrlMatches(sub.sourceUrl, result.feedUrl),
        );
        // 检查是否正在订阅
        final isSubscribing = result.feedUrl != null &&
            subscriptionState.subscribingFeedUrls.any(
              (url) => PodcastUrlUtils.feedUrlMatches(url, result.feedUrl),
            );
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

/// 浮动国家选择器 Overlay
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

    // 计算搜索栏的实际宽度（考虑padding）
    final searchBarWidth = screenWidth - 16; // 搜索栏的padding是8*2=16

    // 下拉框宽度不超过搜索栏宽度，同时不超过360
    final selectorWidth = searchBarWidth.clamp(200.0, 360.0);

    // 计算搜索栏的左边界位置
    // 按钮位置 - SearchBar的左padding(8) = 搜索栏左边界
    final searchBarLeft = buttonOffset.dx - 8.0;

    // 下拉框与搜索栏左对齐
    double left = searchBarLeft;
    double top = buttonOffset.dy + buttonSize.height + 8;

    // 确保下拉框不超出屏幕右边界
    if (left + selectorWidth > screenWidth - 8) {
      left = screenWidth - selectorWidth - 8;
    }
    // 确保下拉框不超出屏幕左边界
    if (left < 8) {
      left = 8;
    }

    return GestureDetector(
      onTap: onDismiss,
      behavior: HitTestBehavior.translucent,
      child: Stack(
        children: [
          // 透明背景层（用于点击外部关闭）
          Container(color: Colors.transparent),
          // 浮动选择器
          Positioned(
            left: left,
            top: top,
            child: GestureDetector(
              onTap: () {}, // 阻止事件冒泡到背景层
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
