import 'dart:ui';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';

import '../../../../core/storage/local_storage_service.dart';
import '../../../../core/providers/core_providers.dart';
import '../../data/models/podcast_search_model.dart';

part 'country_selector_provider.g.dart';

/// 国家选择状态
class CountrySelectorState {
  final PodcastCountry selectedCountry;
  final bool isLoading;

  const CountrySelectorState({
    required this.selectedCountry,
    this.isLoading = false,
  });

  CountrySelectorState copyWith({
    PodcastCountry? selectedCountry,
    bool? isLoading,
  }) {
    return CountrySelectorState(
      selectedCountry: selectedCountry ?? this.selectedCountry,
      isLoading: isLoading ?? this.isLoading,
    );
  }
}

/// 国家选择器 Notifier
@riverpod
class CountrySelectorNotifier extends _$CountrySelectorNotifier {
  @override
  CountrySelectorState build() {
    final localStorage = ref.read(localStorageServiceProvider);

    // 加载保存的国家偏好
    _loadSavedCountry(localStorage);

    // 如果没有保存的偏好，使用系统语言作为默认值
    return CountrySelectorState(
      selectedCountry: _getDefaultCountry(),
    );
  }

  /// 获取默认国家（基于系统语言）
  PodcastCountry _getDefaultCountry() {
    final locale = PlatformDispatcher.instance.locale;

    // 中文用户默认中国
    if (locale.languageCode == 'zh') {
      return PodcastCountry.china;
    }

    // 其他默认美国
    return PodcastCountry.usa;
  }

  /// 从本地存储加载保存的国家偏好
  Future<void> _loadSavedCountry(LocalStorageService localStorage) async {
    final savedCountryCode = await localStorage.getString('podcast_search_country');

    if (savedCountryCode != null) {
      final savedCountry = PodcastCountry.values.firstWhere(
        (country) => country.code == savedCountryCode,
        orElse: () => _getDefaultCountry(),
      );

      if (state.selectedCountry != savedCountry) {
        state = CountrySelectorState(selectedCountry: savedCountry);
      }
    }
  }

  /// 选择国家
  Future<void> selectCountry(PodcastCountry country) async {
    final localStorage = ref.read(localStorageServiceProvider);

    state = CountrySelectorState(selectedCountry: country);

    // 保存到本地存储
    await localStorage.saveString('podcast_search_country', country.code);
  }

  /// 获取当前选中的国家
  PodcastCountry get selectedCountry => state.selectedCountry;
}
