import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import '../../data/models/schedule_config_model.dart';
import '../../data/repositories/podcast_repository.dart';
import 'podcast_providers.dart';

part 'global_schedule_provider.g.dart';

/// Global schedule state
class GlobalScheduleState {
  final List<ScheduleConfigResponse> schedules;
  final bool isLoading;
  final String? error;

  const GlobalScheduleState({
    this.schedules = const [],
    this.isLoading = false,
    this.error,
  });

  GlobalScheduleState copyWith({
    List<ScheduleConfigResponse>? schedules,
    bool? isLoading,
    String? error,
  }) {
    return GlobalScheduleState(
      schedules: schedules ?? this.schedules,
      isLoading: isLoading ?? this.isLoading,
      error: error,
    );
  }
}

@riverpod
class GlobalSchedule extends _$GlobalSchedule {
  late PodcastRepository _repository;

  @override
  GlobalScheduleState build() {
    _repository = ref.watch(podcastRepositoryProvider);
    return const GlobalScheduleState();
  }

  /// Load all subscription schedules
  Future<void> loadAllSchedules() async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      final schedules = await _repository.getAllSubscriptionSchedules();
      state = state.copyWith(schedules: schedules, isLoading: false);
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
    }
  }

  /// Batch update subscription schedules
  Future<bool> batchUpdateSchedules(
    List<int> subscriptionIds,
    ScheduleConfigUpdateRequest request,
  ) async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      await _repository.batchUpdateSubscriptionSchedules(
        subscriptionIds,
        request,
      );
      // Reload all schedules to get fresh data
      await loadAllSchedules();
      return true;
    } catch (e) {
      state = state.copyWith(isLoading: false, error: e.toString());
      return false;
    }
  }
}
