import 'package:flutter_riverpod/flutter_riverpod.dart';

/// A mixin for [Notifier] subclasses that provides in-flight request
/// deduplication, similar to [CachedAsyncNotifier] but for notifiers
/// that manage their own loading/error state within the state model
/// (e.g. [PaginatedState]).
///
/// Usage:
/// ```dart
/// class MyNotifier extends Notifier<MyState> with DeduplicatingNotifier {
///   @override
///   MyState build() => const MyState();
///
///   Future<void> loadData() async {
///     await deduplicate(() async {
///       state = state.copyWith(isLoading: true);
///       final data = await repository.fetch();
///       state = state.copyWith(items: data, isLoading: false);
///     });
///   }
/// }
/// ```
mixin DeduplicatingNotifier<T> on Notifier<T> {
  Future<void>? _inFlightRequest;

  /// Runs [action] with deduplication.
  ///
  /// If a previous call is still in-flight, this returns immediately
  /// without running [action] again. Once [action] completes, the
  /// in-flight reference is cleared.
  Future<void> deduplicate(Future<void> Function() action) async {
    final existing = _inFlightRequest;
    if (existing != null) return existing;

    final future = action();
    _inFlightRequest = future;
    try {
      await future;
    } finally {
      if (identical(_inFlightRequest, future)) {
        _inFlightRequest = null;
      }
    }
  }

  /// Resets the in-flight dedup state. Call on dispose or cache reset.
  void resetDedup() {
    _inFlightRequest = null;
  }
}
