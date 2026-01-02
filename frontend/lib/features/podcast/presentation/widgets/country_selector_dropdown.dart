import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../../../core/localization/app_localizations.dart';
import '../../data/models/podcast_search_model.dart';
import '../providers/country_selector_provider.dart';

/// 国家/地区选择器下拉菜单
///
/// 仿照图片设计：
/// 1. 顶部显示当前选中国家（带下拉箭头）
/// 2. 常用地区：水平滚动的快捷按钮（带国旗）
/// 3. 所有地区：可滚动列表（显示国家代码+名称+对勾）
class CountrySelectorDropdown extends ConsumerStatefulWidget {
  const CountrySelectorDropdown({
    super.key,
    this.onCountryChanged,
  });

  final ValueChanged<PodcastCountry>? onCountryChanged;

  @override
  ConsumerState<CountrySelectorDropdown> createState() =>
      _CountrySelectorDropdownState();
}

class _CountrySelectorDropdownState
    extends ConsumerState<CountrySelectorDropdown> {
  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    final countryState = ref.watch(countrySelectorProvider);
    final countryNotifier = ref.read(countrySelectorProvider.notifier);

    return Container(
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: Theme.of(context).colorScheme.outlineVariant,
          width: 1,
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          // 所有地区
          _buildAllRegionsSection(
            context,
            countryState.selectedCountry,
            countryNotifier,
            l10n,
          ),
        ],
      ),
    );
  }

  /// 构建所有地区部分
  Widget _buildAllRegionsSection(
    BuildContext context,
    PodcastCountry selectedCountry,
    CountrySelectorNotifier countryNotifier,
    AppLocalizations l10n,
  ) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // 标题
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
            child: Text(
              l10n.podcast_country_label,
              style: TextStyle(
                fontSize: 13,
                fontWeight: FontWeight.w600,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          // 所有地区列表（可滚动）
          SizedBox(
            height: MediaQuery.of(context).size.height * 0.5,
            child: ListView.separated(
              itemCount: PodcastCountry.values.length,
              padding: EdgeInsets.zero,
              separatorBuilder: (_, _) => Divider(
                height: 1,
                color: Theme.of(context).colorScheme.outlineVariant,
                indent: 52,
              ),
              itemBuilder: (context, index) {
                final country = PodcastCountry.values[index];
                final isSelected = country == selectedCountry;

                return _buildAllRegionItem(
                  context,
                  country,
                  isSelected,
                  () => _selectCountry(country, countryNotifier),
                );
              },
            ),
          ),
        ],
      ),
    );
  }

  /// 构建所有地区列表项
  Widget _buildAllRegionItem(
    BuildContext context,
    PodcastCountry country,
    bool isSelected,
    VoidCallback onTap,
  ) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        color: isSelected
            ? Theme.of(context).colorScheme.primaryContainer.withValues(alpha: 0.3)
            : null,
        child: Row(
          children: [
            // 国家代码
            SizedBox(
              width: 40,
              child: Text(
                country.code.toUpperCase(),
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.bold,
                  color: isSelected
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
            const SizedBox(width: 16),
            // 国家名称
            Expanded(
              child: Text(
                _getCountryName(country, AppLocalizations.of(context)!),
                style: TextStyle(
                  fontSize: 14,
                  fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                  color: isSelected
                      ? Theme.of(context).colorScheme.primary
                      : Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
            // 选中标记
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
  }

  /// 选择国家
  void _selectCountry(PodcastCountry country, CountrySelectorNotifier countryNotifier) {
    countryNotifier.selectCountry(country);
    widget.onCountryChanged?.call(country);
  }

  /// 获取国家名称
  String _getCountryName(PodcastCountry country, AppLocalizations l10n) {
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
