import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';
import '../providers/country_selector_provider.dart';

/// 国家选择器组件
///
/// 使用 Material 3 SegmentedButton 实现国家/地区选择
class CountrySelector extends ConsumerWidget {
  const CountrySelector({
    super.key,
    this.onCountryChanged,
  });

  final ValueChanged<PodcastCountry>? onCountryChanged;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context)!;
    final countryState = ref.watch(countrySelectorProvider);
    final countryNotifier = ref.read(countrySelectorProvider.notifier);

    return SegmentedButton<PodcastCountry>(
      segments: [
        ButtonSegment(
          value: PodcastCountry.china,
          label: Text(
            l10n.podcast_country_china,
            style: const TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
          icon: const Icon(Icons.public, size: 18),
        ),
        ButtonSegment(
          value: PodcastCountry.usa,
          label: Text(
            l10n.podcast_country_usa,
            style: const TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w500,
            ),
          ),
          icon: const Icon(Icons.public, size: 18),
        ),
      ],
      selected: {countryState.selectedCountry},
      onSelectionChanged: (Set<PodcastCountry> newSelection) {
        final newCountry = newSelection.first;
        countryNotifier.selectCountry(newCountry);

        // 通知父组件
        onCountryChanged?.call(newCountry);
      },
      style: ButtonStyle(
        padding: const WidgetStatePropertyAll<EdgeInsets>(
          EdgeInsets.symmetric(horizontal: 8, vertical: 8),
        ),
      ),
    );
  }
}
