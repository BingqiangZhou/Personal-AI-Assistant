import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import '../../data/models/schedule_config_model.dart';
import '../../data/repositories/podcast_repository.dart';
import 'podcast_providers.dart';

part 'schedule_provider.g.dart';

/// Schedule configuration state
class ScheduleConfigState {
  final ScheduleConfigResponse? config;
  final bool isLoading;
  final String? error;
  final bool isSaving;

  const ScheduleConfigState({
    this.config,
    this.isLoading = false,
    this.error,
    this.isSaving = false,
  });

  ScheduleConfigState copyWith({
    ScheduleConfigResponse? config,
    bool? isLoading,
    String? error,
    bool? isSaving,
  }) {
    return ScheduleConfigState(
      config: config ?? this.config,
      isLoading: isLoading ?? this.isLoading,
      error: error,
      isSaving: isSaving ?? this.isSaving,
    );
  }
}

/// Schedule configuration notifier
@riverpod
class ScheduleConfig extends _$ScheduleConfig {
  late PodcastRepository _repository;

  @override
  ScheduleConfigState build() {
    _repository = ref.watch(podcastRepositoryProvider);
    return const ScheduleConfigState();
  }

  /// Load schedule configuration for a subscription
  Future<void> loadConfig(int subscriptionId) async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      final config = await _repository.getSubscriptionSchedule(subscriptionId);
      state = state.copyWith(config: config, isLoading: false);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }

  /// Update schedule configuration
  Future<bool> updateConfig(
    int subscriptionId,
    ScheduleConfigUpdateRequest request,
  ) async {
    state = state.copyWith(isSaving: true, error: null);
    try {
      final config = await _repository.updateSubscriptionSchedule(
        subscriptionId,
        request,
      );
      state = state.copyWith(config: config, isSaving: false);
      return true;
    } catch (e) {
      state = state.copyWith(isSaving: false, error: e.toString());
      return false;
    }
  }

  /// Clear error
  void clearError() {
    state = state.copyWith(error: null);
  }
}

/// Provider for subscription ID
final subscriptionIdProvider = Provider<int>((ref) {
  throw UnimplementedError('subscriptionIdProvider must be overridden');
});
