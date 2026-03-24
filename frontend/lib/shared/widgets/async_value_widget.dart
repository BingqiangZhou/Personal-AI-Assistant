import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

/// A reusable widget for handling AsyncValue states from Riverpod providers.
///
/// This widget provides a consistent way to handle loading, error, and data
/// states for AsyncValue objects, reducing boilerplate in UI code.
///
/// Example usage:
/// ```dart
/// AsyncValueWidget(
///   value: highlightsProvider,
///   builder: (data) => ListView.builder(...),
///   loadingWidget: CircularProgressIndicator(),
///   errorBuilder: (error, stack) => Text('Error: $error'),
/// )
/// ```
class AsyncValueWidget<T> extends StatelessWidget {
  /// The AsyncValue to observe
  final AsyncValue<T> value;

  /// Builder for successful data state
  final Widget Function(T data) builder;

  /// Widget to show during loading state
  final Widget? loadingWidget;

  /// Builder for error state
  final Widget Function(Object error, StackTrace stack)? errorBuilder;

  /// Whether to skip loading state if there's previous data
  ///
  /// When true, shows previous data while loading instead of loading widget.
  /// Useful for refresh scenarios where you want to keep showing old data.
  final bool skipLoadingWhenData;

  const AsyncValueWidget({
    super.key,
    required this.value,
    required this.builder,
    this.loadingWidget,
    this.errorBuilder,
    this.skipLoadingWhenData = false,
  });

  @override
  Widget build(BuildContext context) {
    // Skip loading if we have previous data and skipLoadingWhenData is true
    if (value.isLoading && value.hasValue && skipLoadingWhenData) {
      return builder(value.value as T);
    }

    return value.when(
      data: builder,
      loading: () => loadingWidget ?? _defaultLoadingWidget(context),
      error: (error, stack) => errorBuilder != null
          ? errorBuilder!(error, stack)
          : _defaultErrorWidget(context, error, stack),
    );
  }

  Widget _defaultLoadingWidget(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: CircularProgressIndicator(
        color: theme.colorScheme.primary,
      ),
    );
  }

  Widget _defaultErrorWidget(BuildContext context, Object error, StackTrace stack) {
    final theme = Theme.of(context);
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              Icons.error_outline,
              color: theme.colorScheme.error,
              size: 48,
            ),
            const SizedBox(height: 16),
            Text(
              'An error occurred',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 8),
            Text(
              error.toString(),
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }
}

/// A specialized version of AsyncValueWidget for nullable data types.
///
/// This handles the case where T might be null, providing additional
/// empty state handling.
class AsyncValueNullableWidget<T> extends StatelessWidget {
  final AsyncValue<T?> value;
  final Widget Function(T data) builder;
  final Widget? loadingWidget;
  final Widget Function(Object error, StackTrace stack)? errorBuilder;
  final Widget Function()? emptyBuilder;
  final bool skipLoadingWhenData;

  const AsyncValueNullableWidget({
    super.key,
    required this.value,
    required this.builder,
    this.loadingWidget,
    this.errorBuilder,
    this.emptyBuilder,
    this.skipLoadingWhenData = false,
  });

  @override
  Widget build(BuildContext context) {
    return AsyncValueWidget<T?>(
      value: value,
      loadingWidget: loadingWidget,
      errorBuilder: errorBuilder,
      skipLoadingWhenData: skipLoadingWhenData,
      builder: (data) {
        if (data == null) {
          return emptyBuilder?.call() ?? _defaultEmptyWidget(context);
        }
        return builder(data);
      },
    );
  }

  Widget _defaultEmptyWidget(BuildContext context) {
    final theme = Theme.of(context);
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.inbox_outlined,
            color: theme.colorScheme.onSurfaceVariant,
            size: 48,
          ),
          const SizedBox(height: 16),
          Text(
            'No data available',
            style: theme.textTheme.bodyLarge?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ],
      ),
    );
  }
}
