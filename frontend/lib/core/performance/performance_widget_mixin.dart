import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';

import 'performance_monitor.dart';
import '../utils/app_logger.dart' as logger;

/// Mixin to automatically track widget build performance.
///
/// This mixin tracks build times and logs warnings for slow builds.
/// It also counts rebuild frequency to detect excessive rebuilds.
///
/// Example usage:
/// ```dart
/// class MyWidget extends StatefulWidget {
///   const MyWidget({super.key});
///   @override
///   State<MyWidget> createState() => _MyWidgetState();
/// }
///
/// class _MyWidgetState extends State<MyWidget>
///     with PerformanceWidgetMixin {
///   @override
///   Widget build(BuildContext context) {
///     return buildWithPerformance(
///       context,
///       () => Text('Hello'),
///     );
///   }
/// }
/// ```
mixin PerformanceWidgetMixin<T extends StatefulWidget> on State<T> {
  /// Logger tag for this mixin.
  String get _performanceTag => 'PerformanceWidgetMixin';

  /// Counter for number of rebuilds.
  int _buildCount = 0;

  /// Timestamp of first build.
  DateTime? _firstBuildTime;

  /// Timestamp of last build.
  DateTime? _lastBuildTime;

  /// Whether to enable performance tracking for this widget.
  ///
  /// Override this to return false to disable tracking for specific widgets.
  bool get performanceTrackingEnabled => kDebugMode;

  /// Get the name of this widget for logging purposes.
  ///
  /// Override this to provide a custom name. Defaults to the runtime type.
  String get performanceWidgetName => widget.runtimeType.toString();

  /// Track the current build and return the widget.
  ///
  /// Wrap your build method's return value with this method to enable tracking.
  ///
  /// Example:
  /// ```dart
  /// @override
  /// Widget build(BuildContext context) {
  ///   return buildWithPerformance(
  ///     context,
  ///     () => YourWidget(...),
  ///   );
  /// }
  /// ```
  Widget buildWithPerformance(
    BuildContext context,
    Widget Function() builder,
  ) {
    if (!performanceTrackingEnabled) {
      return builder();
    }

    final stopwatch = Stopwatch()..start();
    _buildCount++;
    final now = DateTime.now();
    _firstBuildTime ??= now;
    _lastBuildTime = now;

    try {
      return builder();
    } finally {
      stopwatch.stop();
      _trackBuild(stopwatch.elapsed);
    }
  }

  /// Track the build time and log if slow.
  void _trackBuild(Duration buildTime) {
    PerformanceMonitor.instance.trackWidgetBuild(
      performanceWidgetName,
      buildTime,
    );

    // Warn about excessive rebuilds
    if (_buildCount > 100) {
      final timeSinceFirstBuild = DateTime.now().difference(_firstBuildTime!);
      final rebuildsPerSecond = _buildCount / timeSinceFirstBuild.inSeconds;

      if (rebuildsPerSecond > 10) {
        logger.AppLogger.warning(
          '[EXCESSIVE REBUILDS] "$performanceWidgetName" has rebuilt '
          '$_buildCount times in ${timeSinceFirstBuild.inSeconds}s '
          '(~${rebuildsPerSecond.toStringAsFixed(1)} rebuilds/sec)',
          tag: _performanceTag,
        );
      }
    }
  }

  /// Get the current build count.
  int get buildCount => _buildCount;

  /// Get the time since the first build.
  Duration? get timeSinceFirstBuild {
    if (_firstBuildTime == null) return null;
    return DateTime.now().difference(_firstBuildTime!);
  }

  /// Get the time since the last build.
  Duration? get timeSinceLastBuild {
    if (_lastBuildTime == null) return null;
    return DateTime.now().difference(_lastBuildTime!);
  }

  @override
  void dispose() {
    if (performanceTrackingEnabled && kDebugMode) {
      // Log final stats
      final timeSinceFirst = timeSinceFirstBuild;
      if (timeSinceFirst != null && _buildCount > 1) {
        final avgRebuildRate = _buildCount / timeSinceFirst.inSeconds;
        logger.AppLogger.debug(
          '[WIDGET LIFECYCLE] "$performanceWidgetName" - '
          'builds: $_buildCount, '
          'lifetime: ${timeSinceFirst.inSeconds}s, '
          'avg rate: ${avgRebuildRate.toStringAsFixed(2)} builds/sec',
          tag: _performanceTag,
        );
      }
    }
    super.dispose();
  }
}

/// A base class for stateful widgets that want automatic performance tracking.
///
/// Simply extend this class instead of StatefulWidget to get automatic
/// build performance tracking.
///
/// Example:
/// ```dart
/// class MyWidget extends PerformanceStatefulWidget {
///   const MyWidget({super.key});
///
///   @override
///   State<MyWidget> createState() => _MyWidgetState();
/// }
///
/// class _MyWidgetState extends PerformanceWidgetState<MyWidget> {
///   @override
///   Widget buildContent(BuildContext context) {
///     return Text('Hello');
///   }
/// }
/// ```
abstract class PerformanceStatefulWidget extends StatefulWidget {
  const PerformanceStatefulWidget({super.key});

  @override
  State<PerformanceStatefulWidget> createState();
}

/// Base state class for performance-tracked widgets.
abstract class PerformanceWidgetState<T extends PerformanceStatefulWidget>
    extends State<T> with PerformanceWidgetMixin {
  /// Override this method to build your widget.
  ///
  /// Performance tracking is automatic.
  @mustCallSuper
  Widget buildContent(BuildContext context);

  @override
  Widget build(BuildContext context) {
    return buildWithPerformance(context, () => buildContent(context));
  }
}
