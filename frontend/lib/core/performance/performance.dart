/// Performance monitoring module for tracking widget builds and provider rebuilds.
///
/// This module provides tools to monitor and optimize app performance:
/// - [PerformanceMonitor]: Central service for tracking performance metrics
/// - [PerformanceWidgetMixin]: Mixin for automatic widget build tracking
/// - [ProviderPerformanceObserver]: Observer for provider rebuild monitoring
///
/// Example usage:
/// ```dart
/// // In main.dart
/// ProviderScope(
///   observers: [ProviderPerformanceObserver()],
///   child: MyApp(),
/// )
///
/// // In widgets
/// class MyWidget extends StatefulWidget {
///   @override
///   State<MyWidget> createState() => _MyWidgetState();
/// }
///
/// class _MyWidgetState extends State<MyWidget> with PerformanceWidgetMixin {
///   @override
///   Widget build(BuildContext context) {
///     return buildWithPerformance(context, () => YourWidget());
///   }
/// }
///
/// // Manual tracking
/// PerformanceMonitor.instance.trackWidgetBuild('MyWidget', duration);
/// ```
library;

export 'performance_monitor.dart';
export 'performance_widget_mixin.dart';
export 'provider_performance_observer.dart';
