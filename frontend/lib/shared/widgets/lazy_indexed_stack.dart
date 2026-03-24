import 'package:flutter/material.dart';

/// A lazy-loading version of [IndexedStack] that only builds widgets
/// for tabs that have been visited.
///
/// This widget improves initial loading time and reduces memory usage
/// by deferring the construction of tab content until the tab is
/// first accessed. Once a tab is built, its state is preserved
/// when switching between tabs.
///
/// Example:
/// ```dart
/// LazyIndexedStack(
///   index: _currentIndex,
///   itemCount: 3,
///   itemBuilder: (context, index) {
///     switch (index) {
///       case 0: return const TabOne();
///       case 1: return const TabTwo();
///       case 2: return const TabThree();
///       default: return const SizedBox.shrink();
///     }
///   },
/// )
/// ```
///
/// See also:
///   - [IndexedStack], which builds all children immediately
class LazyIndexedStack extends StatefulWidget {
  /// The index of the currently visible child.
  ///
  /// When this value changes, the widget at the new index becomes visible.
  /// If the new index has not been visited before, its content will be built.
  final int index;

  /// The total number of potential children.
  ///
  /// This determines how many tabs can be accessed.
  final int itemCount;

  /// Builds the widget for the given [index].
  ///
  /// This is only called when the tab at [index] is first visited.
  /// Subsequent switches to the same tab will reuse the previously built widget.
  final NullableWidgetBuilder itemBuilder;

  /// Optional callback invoked when a tab is visited for the first time.
  ///
  /// This can be used for analytics, prefetching, or other side effects.
  final ValueChanged<int>? onTabVisited;

  const LazyIndexedStack({
    super.key,
    required this.index,
    required this.itemCount,
    required this.itemBuilder,
    this.onTabVisited,
  });

  @override
  State<LazyIndexedStack> createState() => _LazyIndexedStackState();
}

class _LazyIndexedStackState extends State<LazyIndexedStack> {
  late final Set<int> _visitedTabs;
  late int _currentIndex;

  @override
  void initState() {
    super.initState();
    _currentIndex = widget.index;
    _visitedTabs = {_currentIndex};
  }

  @override
  void didUpdateWidget(LazyIndexedStack oldWidget) {
    super.didUpdateWidget(oldWidget);
    final newIndex = widget.index;

    if (_currentIndex != newIndex) {
      setState(() {
        _currentIndex = newIndex;
        if (!_visitedTabs.contains(newIndex)) {
          _visitedTabs.add(newIndex);
          widget.onTabVisited?.call(newIndex);
        }
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return IndexedStack(
      index: widget.index,
      children: List<Widget>.generate(
        widget.itemCount,
        (index) {
          // Only build content for visited tabs
          if (!_visitedTabs.contains(index)) {
            return const SizedBox.shrink();
          }
          return widget.itemBuilder(context, index) ?? const SizedBox.shrink();
        },
      ),
    );
  }
}

/// Signature for a function that builds a widget, potentially returning null.
///
/// This is similar to [WidgetBuilder] but allows for nullable return types,
/// which is useful for conditional widget construction.
typedef NullableWidgetBuilder = Widget? Function(BuildContext context, int index);
