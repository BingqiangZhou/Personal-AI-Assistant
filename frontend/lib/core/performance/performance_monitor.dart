import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';

import '../utils/app_logger.dart' as logger;

/// Threshold for considering a widget build as "slow" (one frame at 60fps).
const Duration _slowBuildThreshold = Duration(milliseconds: 16);

/// Threshold for considering a provider rebuild as "high frequency".
const int _highRebuildFrequencyThreshold = 10;

/// Performance monitoring service for tracking widget builds and provider rebuilds.
///
/// This class collects performance metrics and logs warnings when
/// operations exceed acceptable thresholds.
///
/// Example usage:
/// ```dart
/// PerformanceMonitor.instance.trackWidgetBuild('MyWidget', buildTime);
/// PerformanceMonitor.instance.trackProviderRebuild('myProvider', listeners);
/// ```
class PerformanceMonitor {
  PerformanceMonitor._() {
    _tag = 'PerformanceMonitor';
  }

  /// Singleton instance.
  static final instance = PerformanceMonitor._();

  late final String _tag;

  /// Statistics for widget builds.
  final Map<String, WidgetBuildStats> _widgetStats = {};

  /// Statistics for provider rebuilds.
  final Map<String, ProviderRebuildStats> _providerStats = {};

  /// Whether performance monitoring is enabled.
  bool _enabled = kDebugMode;

  /// Enable or disable performance monitoring.
  void setEnabled(bool enabled) {
    _enabled = enabled;
    logger.AppLogger.debug(
      'Performance monitoring ${enabled ? "enabled" : "disabled"}',
      tag: _tag,
    );
  }

  /// Check if performance monitoring is enabled.
  bool get isEnabled => _enabled;

  /// Track a widget build time.
  ///
  /// Logs a warning if the build time exceeds 16ms (one frame at 60fps).
  void trackWidgetBuild(String widgetName, Duration buildTime) {
    if (!_enabled) return;

    final stats = _widgetStats.putIfAbsent(
      widgetName,
      () => WidgetBuildStats(),
    );

    stats.recordBuild(buildTime);

    if (buildTime > _slowBuildThreshold) {
      logger.AppLogger.warning(
        '[SLOW BUILD] "$widgetName" took ${buildTime.inMilliseconds}ms '
        '(threshold: ${_slowBuildThreshold.inMilliseconds}ms)',
        tag: _tag,
      );
    }

    // Log summary every 100 builds
    if (stats.totalBuilds % 100 == 0) {
      logger.AppLogger.info(
        '[BUILD STATS] "$widgetName" - '
        'builds: ${stats.totalBuilds}, '
        'avg: ${stats.averageBuildTime.inMilliseconds}ms, '
        'max: ${stats.maxBuildTime.inMilliseconds}ms, '
        'slow: ${stats.slowBuilds}',
        tag: _tag,
      );
    }
  }

  /// Track a provider rebuild.
  ///
  /// Logs a warning if the provider has too many listeners (high frequency).
  void trackProviderRebuild(String providerName, int listenerCount) {
    if (!_enabled) return;

    final stats = _providerStats.putIfAbsent(
      providerName,
      () => ProviderRebuildStats(),
    );

    stats.recordRebuild(listenerCount);

    if (listenerCount >= _highRebuildFrequencyThreshold) {
      logger.AppLogger.warning(
        '[HIGH FREQUENCY] "$providerName" has $listenerCount listeners '
        '(threshold: $_highRebuildFrequencyThreshold)',
        tag: _tag,
      );
    }

    // Log summary every 100 rebuilds
    if (stats.totalRebuilds % 100 == 0) {
      logger.AppLogger.info(
        '[PROVIDER STATS] "$providerName" - '
        'rebuilds: ${stats.totalRebuilds}, '
        'avg listeners: ${stats.averageListenerCount.toStringAsFixed(1)}, '
        'max listeners: ${stats.maxListenerCount}',
        tag: _tag,
      );
    }
  }

  /// Get statistics for a specific widget.
  WidgetBuildStats? getWidgetStats(String widgetName) {
    return _widgetStats[widgetName];
  }

  /// Get statistics for a specific provider.
  ProviderRebuildStats? getProviderStats(String providerName) {
    return _providerStats[providerName];
  }

  /// Get all widget statistics.
  Map<String, WidgetBuildStats> getAllWidgetStats() {
    return Map.unmodifiable(_widgetStats);
  }

  /// Get all provider statistics.
  Map<String, ProviderRebuildStats> getAllProviderStats() {
    return Map.unmodifiable(_providerStats);
  }

  /// Clear all statistics.
  void clearStats() {
    _widgetStats.clear();
    _providerStats.clear();
    logger.AppLogger.debug('All performance statistics cleared', tag: _tag);
  }

  /// Log a summary of all collected statistics.
  void logSummary() {
    if (!_enabled) return;

    logger.AppLogger.info('=== Performance Summary ===', tag: _tag);

    if (_widgetStats.isNotEmpty) {
      logger.AppLogger.info('Widget Builds:', tag: _tag);
      _widgetStats.forEach((name, stats) {
        logger.AppLogger.info(
          '  "$name": '
          'builds: ${stats.totalBuilds}, '
          'avg: ${stats.averageBuildTime.inMilliseconds}ms, '
          'slow: ${stats.slowBuilds}',
          tag: _tag,
        );
      });
    }

    if (_providerStats.isNotEmpty) {
      logger.AppLogger.info('Provider Rebuilds:', tag: _tag);
      _providerStats.forEach((name, stats) {
        logger.AppLogger.info(
          '  "$name": '
          'rebuilds: ${stats.totalRebuilds}, '
          'avg listeners: ${stats.averageListenerCount.toStringAsFixed(1)}',
          tag: _tag,
        );
      });
    }

    logger.AppLogger.info('========================', tag: _tag);
  }
}

/// Statistics for widget builds.
class WidgetBuildStats {
  int totalBuilds = 0;
  Duration totalBuildTime = Duration.zero;
  Duration maxBuildTime = Duration.zero;
  int slowBuilds = 0;

  void recordBuild(Duration buildTime) {
    totalBuilds++;
    totalBuildTime += buildTime;

    if (buildTime > maxBuildTime) {
      maxBuildTime = buildTime;
    }

    if (buildTime > _slowBuildThreshold) {
      slowBuilds++;
    }
  }

  Duration get averageBuildTime {
    if (totalBuilds == 0) return Duration.zero;
    return Duration(
      microseconds: totalBuildTime.inMicroseconds ~/ totalBuilds,
    );
  }
}

/// Statistics for provider rebuilds.
class ProviderRebuildStats {
  int totalRebuilds = 0;
  int totalListeners = 0;
  int maxListenerCount = 0;

  void recordRebuild(int listenerCount) {
    totalRebuilds++;
    totalListeners += listenerCount;

    if (listenerCount > maxListenerCount) {
      maxListenerCount = listenerCount;
    }
  }

  double get averageListenerCount {
    if (totalRebuilds == 0) return 0.0;
    return totalListeners / totalRebuilds;
  }
}

/// Extension to get PerformanceMonitor instance easily.
extension PerformanceMonitorExtension on PerformanceMonitor {
  /// Track a widget build from a build method.
  Widget trackBuild(
    String widgetName,
    Widget Function() buildFn,
  ) {
    if (!_enabled) {
      return buildFn();
    }

    final stopwatch = Stopwatch()..start();
    try {
      return buildFn();
    } finally {
      stopwatch.stop();
      trackWidgetBuild(widgetName, stopwatch.elapsed);
    }
  }
}
