import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'performance_monitor.dart';
import '../utils/app_logger.dart' as logger;

/// Observer for tracking provider rebuild performance.
///
/// This observer monitors provider rebuilds and listener counts,
/// logging warnings for high-frequency rebuilds.
///
/// Example usage:
/// ```dart
/// ProviderScope(
///   observers: [
///     ProviderPerformanceObserver(),
///   ],
///   child: MyApp(),
/// )
/// ```
base class ProviderPerformanceObserver extends ProviderObserver {
  /// Whether performance monitoring is enabled.
  final bool enabled;

  /// Threshold for logging warnings about listener count.
  final int listenerWarningThreshold;

  /// Logger tag for this observer.
  final String _tag;

  /// Create a new provider performance observer.
  ProviderPerformanceObserver({
    this.enabled = kDebugMode,
    this.listenerWarningThreshold = 10,
  }) : _tag = 'ProviderPerformanceObserver';

  @override
  void didAddProvider(
    ProviderObserverContext context,
    Object? value,
  ) {
    if (!enabled) return;
    final providerName = context.provider.name ?? 'unknown';
    logger.AppLogger.debug(
      '[PROVIDER] Added: $providerName',
      tag: _tag,
    );
  }

  @override
  void didDisposeProvider(ProviderObserverContext context) {
    if (!enabled) return;
    final providerName = context.provider.name ?? 'unknown';
    logger.AppLogger.debug(
      '[PROVIDER] Disposed: $providerName',
      tag: _tag,
    );
  }

  @override
  void providerDidFail(
    ProviderObserverContext context,
    Object error,
    StackTrace stackTrace,
  ) {
    if (!enabled) return;
    final providerName = context.provider.name ?? 'unknown';
    logger.AppLogger.error(
      '[PROVIDER] Error in $providerName: $error',
      tag: _tag,
    );
  }

  @override
  void didUpdateProvider(
    ProviderObserverContext context,
    Object? previousValue,
    Object? newValue,
  ) {
    if (!enabled) return;

    // Track the provider rebuild
    final providerName = context.provider.name ?? 'unknown';
    PerformanceMonitor.instance.trackProviderRebuild(
      providerName,
      1, // Approximate listener count
    );
  }
}

/// A more detailed provider observer that tracks rebuild frequency over time.
///
/// This observer maintains a history of rebuilds and can detect
/// providers that are rebuilding too frequently.
base class DetailedProviderObserver extends ProviderObserver {
  /// Map of provider names to their rebuild history.
  final Map<String, List<DateTime>> _rebuildHistory = {};

  /// Time window for tracking rebuild frequency.
  final Duration trackingWindow;

  /// Threshold for logging warnings about rebuild frequency.
  final int rebuildWarningThreshold;

  /// Whether performance monitoring is enabled.
  final bool enabled;

  /// Logger tag for this observer.
  final String _tag;

  DetailedProviderObserver({
    this.enabled = kDebugMode,
    this.trackingWindow = const Duration(seconds: 5),
    this.rebuildWarningThreshold = 20,
  }) : _tag = 'DetailedProviderObserver';

  @override
  void didUpdateProvider(
    ProviderObserverContext context,
    Object? previousValue,
    Object? newValue,
  ) {
    if (!enabled) return;

    final providerName = context.provider.name ?? 'unknown';
    final now = DateTime.now();

    // Add to rebuild history
    _rebuildHistory.putIfAbsent(providerName, () => []).add(now);

    // Get history list (guaranteed to exist after putIfAbsent)
    final history = _rebuildHistory[providerName];
    if (history == null) return;

    // Clean old rebuilds outside the tracking window
    history.removeWhere(
      (time) => now.difference(time) > trackingWindow,
    );

    // Check if rebuild frequency is too high
    final recentRebuilds = history.length;
    if (recentRebuilds > rebuildWarningThreshold) {
      logger.AppLogger.warning(
        '[HIGH REBUILD FREQUENCY] "$providerName" has rebuilt '
        '$recentRebuilds times in the last ${trackingWindow.inSeconds}s '
        '(threshold: $rebuildWarningThreshold)',
        tag: _tag,
      );
    }
  }

  @override
  void didDisposeProvider(ProviderObserverContext context) {
    if (!enabled) return;
    final providerName = context.provider.name ?? 'unknown';
    _rebuildHistory.remove(providerName);
  }

  /// Get the rebuild history for a specific provider.
  List<DateTime> getRebuildHistory(String providerName) {
    return List.unmodifiable(_rebuildHistory[providerName] ?? []);
  }

  /// Get all provider rebuild histories.
  Map<String, List<DateTime>> getAllRebuildHistories() {
    return Map.unmodifiable(
      _rebuildHistory.map(
        (name, history) => MapEntry(name, List.unmodifiable(history)),
      ),
    );
  }

  /// Clear all rebuild histories.
  void clearHistories() {
    _rebuildHistory.clear();
  }
}
