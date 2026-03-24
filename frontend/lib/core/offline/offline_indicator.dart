import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'connectivity_provider.dart';

/// Offline indicator widget showing network status
class OfflineIndicator extends ConsumerWidget {
  const OfflineIndicator({
    super.key,
    this.position = OfflineIndicatorPosition.top,
    this.showWhenOnline = false,
    this.duration,
  });

  final OfflineIndicatorPosition position;
  final bool showWhenOnline;
  final Duration? duration;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final connectivity = ref.watch(connectivityProvider);
    final isOnline = connectivity.isOnline;

    // Don't show if online and showWhenOnline is false
    if (isOnline && !showWhenOnline) {
      return const SizedBox.shrink();
    }

    final message = isOnline ? 'Back online' : 'No internet connection';
    final icon = isOnline ? Icons.cloud_done : Icons.cloud_off;
    final backgroundColor = isOnline
        ? Colors.green.shade700
        : Theme.of(context).colorScheme.errorContainer;

    final banner = Material(
      color: backgroundColor,
      elevation: 4,
      child: SafeArea(
        bottom: position == OfflineIndicatorPosition.bottom,
        top: position == OfflineIndicatorPosition.top,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(
                icon,
                color: Colors.white,
                size: 18,
              ),
              const SizedBox(width: 8),
              Text(
                message,
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 13,
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );

    if (duration != null) {
      return _TemporarilyVisible(
        duration: duration!,
        child: banner,
      );
    }

    return banner;
  }
}

/// Position of the offline indicator
enum OfflineIndicatorPosition {
  top,
  bottom,
}

/// Widget that temporarily shows its child and then disappears
class _TemporarilyVisible extends StatefulWidget {
  const _TemporarilyVisible({
    required this.child,
    required this.duration,
  });

  final Widget child;
  final Duration duration;

  @override
  State<_TemporarilyVisible> createState() => _TemporarilyVisibleState();
}

class _TemporarilyVisibleState extends State<_TemporarilyVisible> {
  bool _isVisible = true;

  @override
  void initState() {
    super.initState();
    Future.delayed(widget.duration, () {
      if (mounted) {
        setState(() => _isVisible = false);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return _isVisible ? widget.child : const SizedBox.shrink();
  }
}

/// Offline banner that appears at the top of the screen
class OfflineBanner extends ConsumerWidget {
  const OfflineBanner({
    super.key,
    this.showWhenOnline = true,
    this.onlineDuration = const Duration(seconds: 3),
  });

  final bool showWhenOnline;
  final Duration onlineDuration;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    return OfflineIndicator(
      position: OfflineIndicatorPosition.top,
      showWhenOnline: showWhenOnline,
      duration: onlineDuration,
    );
  }
}

/// Compact offline status indicator for app bar
class OfflineStatusIndicator extends ConsumerWidget {
  const OfflineStatusIndicator({
    super.key,
    this.size = 8,
  });

  final double size;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOnline = ref.watch(isOnlineProvider);

    return Tooltip(
      message: isOnline ? 'Online' : 'Offline',
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: isOnline ? Colors.green : Colors.red,
          boxShadow: [
            BoxShadow(
              color: (isOnline ? Colors.green : Colors.red).withValues(alpha: 0.4),
              blurRadius: 4,
              spreadRadius: 1,
            ),
          ],
        ),
      ),
    );
  }
}

/// Builder that shows different content based on online status
class OnlineBuilder extends ConsumerWidget {
  const OnlineBuilder({
    super.key,
    required this.online,
    required this.offline,
  });

  final WidgetBuilder online;
  final WidgetBuilder offline;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOnline = ref.watch(isOnlineProvider);
    return isOnline ? online(context) : offline(context);
  }
}

/// Wrapper that disables interactions when offline
class OfflineAware extends ConsumerWidget {
  const OfflineAware({
    super.key,
    required this.child,
    this.offlineWidget,
    this.showIndicator = true,
  });

  final Widget child;
  final Widget? offlineWidget;
  final bool showIndicator;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final isOnline = ref.watch(isOnlineProvider);

    if (!isOnline) {
      return offlineWidget ??
          Stack(
            children: [
              child,
              if (showIndicator)
                Positioned(
                  top: 0,
                  left: 0,
                  right: 0,
                  child: IgnorePointer(
                    child: Container(
                      color: Colors.black12,
                      padding: const EdgeInsets.all(8),
                      child: const Center(
                        child: OfflineBanner(showWhenOnline: false),
                      ),
                    ),
                  ),
                ),
            ],
          );
    }

    return child;
  }
}
