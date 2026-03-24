import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../../core/localization/app_localizations_extension.dart';
import '../../constants/podcast_ui_constants.dart';
import '../../providers/podcast_search_provider.dart' as search;
import '../../providers/country_selector_provider.dart';

/// Search input widget for discover page with country selector
class DiscoverSearchInput extends ConsumerWidget {
  const DiscoverSearchInput({
    super.key,
    required this.searchController,
    required this.searchFocusNode,
    required this.onSearchChanged,
    required this.onClearSearch,
    required this.onCountryTap,
    this.searchMode = search.PodcastSearchMode.podcasts,
    this.isDense = false,
  });

  final TextEditingController searchController;
  final FocusNode searchFocusNode;
  final ValueChanged<String> onSearchChanged;
  final VoidCallback onClearSearch;
  final VoidCallback onCountryTap;
  final search.PodcastSearchMode searchMode;
  final bool isDense;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final theme = Theme.of(context);
    final hintLabel = searchMode == search.PodcastSearchMode.episodes
        ? l10n.podcast_search_section_episodes
        : l10n.podcast_search_section_podcasts;
    final isZh = Localizations.localeOf(context).languageCode.startsWith('zh');
    final hintText = isZh
        ? '${l10n.search}$hintLabel...'
        : '${l10n.search} $hintLabel...';

    return RepaintBoundary(
      key: const Key('podcast_discover_search_input_boundary'),
      child: Material(
        key: const Key('podcast_discover_search_bar'),
        color: theme.colorScheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(kPodcastMiniCornerRadius),
          side: BorderSide(color: theme.colorScheme.outlineVariant),
        ),
        child: SizedBox(
        height: isDense ? 44 : 48,
        child: Row(
          children: [
            Padding(
              padding: EdgeInsets.only(left: isDense ? 10 : 12),
              child: Icon(
                Icons.search,
                size: isDense ? 18 : 20,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            SizedBox(width: isDense ? 6 : 8),
            Expanded(
              child: TextField(
                key: const Key('podcast_discover_search_input'),
                controller: searchController,
                focusNode: searchFocusNode,
                textInputAction: TextInputAction.search,
                style: theme.textTheme.bodyMedium,
                decoration: InputDecoration(
                  border: InputBorder.none,
                  enabledBorder: InputBorder.none,
                  focusedBorder: InputBorder.none,
                  disabledBorder: InputBorder.none,
                  errorBorder: InputBorder.none,
                  focusedErrorBorder: InputBorder.none,
                  filled: false,
                  fillColor: Colors.transparent,
                  hintText: hintText,
                  isDense: true,
                  contentPadding: EdgeInsets.zero,
                  hintStyle: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                onChanged: onSearchChanged,
              ),
            ),
            ValueListenableBuilder<TextEditingValue>(
              valueListenable: searchController,
              builder: (context, value, _) {
                if (value.text.isNotEmpty) {
                  return IconButton(
                    onPressed: onClearSearch,
                    icon: Icon(
                      Icons.clear,
                      size: isDense ? 16 : 18,
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  );
                }
                return const SizedBox.shrink();
              },
            ),
            Padding(
              padding: EdgeInsets.only(right: isDense ? 6 : 7),
              child: _CountryButton(
                isDense: isDense,
                onTap: onCountryTap,
              ),
            ),
          ],
        ),
      ),
    ),
    );
  }
}

class _CountryButton extends ConsumerWidget {
  const _CountryButton({
    required this.isDense,
    required this.onTap,
  });

  final bool isDense;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final theme = Theme.of(context);
    final selectedCountry = ref.watch(
      countrySelectorProvider.select((state) => state.selectedCountry),
    );
    final height = isDense ? 30.0 : 32.0;

    return Material(
      color: Colors.transparent,
      child: InkWell(
        key: const Key('podcast_discover_country_button'),
        borderRadius: BorderRadius.circular(height / 2),
        onTap: onTap,
        child: Container(
          height: height,
          padding: const EdgeInsets.symmetric(horizontal: 8),
          decoration: BoxDecoration(
            color: theme.colorScheme.surfaceContainerHighest,
            borderRadius: BorderRadius.circular(height / 2),
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                Icons.flag_outlined,
                size: 14,
                color: theme.colorScheme.onSurfaceVariant,
              ),
              const SizedBox(width: 4),
              Text(
                selectedCountry.code.toUpperCase(),
                style: theme.textTheme.labelSmall?.copyWith(
                  fontWeight: FontWeight.w600,
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(width: 2),
              Icon(
                Icons.keyboard_arrow_down_rounded,
                size: 14,
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ],
          ),
        ),
      ),
    );
  }
}
