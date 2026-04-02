import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/core/offline/connectivity_provider.dart';
import 'package:personal_ai_assistant/core/theme/app_theme.dart';

/// Offline indicator widget showing network status with smooth animations.
class OfflineIndicator extends ConsumerStatefulWidget {
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
  ConsumerState<OfflineIndicator> createState() => _OfflineIndicatorState();
}

class _OfflineIndicatorState extends ConsumerState<OfflineIndicator> {
  bool _hasBeenOffline = false;
  bool _showBanner = false;

  @override
  Widget build(BuildContext context) {
    final connectivity = ref.watch(connectivityProvider);
    final isOnline = connectivity.isOnline;

    // Track offline state to show "back online" message
    if (!isOnline) {
      _hasBeenOffline = true;
      _showBanner = true;
    } else if (_hasBeenOffline && widget.showWhenOnline) {
      _showBanner = true;
    } else if (isOnline && !widget.showWhenOnline) {
      _showBanner = false;
    }

    if (!_showBanner) {
      return AnimatedSlide(
        offset: widget.position == OfflineIndicatorPosition.top
            ? const Offset(0, -1)
            : const Offset(0, 1),
        duration: const Duration(milliseconds: 300),
        curve: Curves.easeInOut,
        child: AnimatedOpacity(
          opacity: 0,
          duration: const Duration(milliseconds: 300),
          child: _buildBanner(context, true),
        ),
      );
    }

    if (widget.duration != null) {
      return _TemporarilyVisible(
        duration: widget.duration!,
        child: AnimatedSlide(
          offset: Offset.zero,
          duration: const Duration(milliseconds: 300),
          curve: Curves.easeInOut,
          child: AnimatedOpacity(
            opacity: 1,
            duration: const Duration(milliseconds: 300),
            child: _buildBanner(context, isOnline),
          ),
        ),
      );
    }

    return AnimatedSlide(
      offset: Offset.zero,
      duration: const Duration(milliseconds: 300),
      curve: Curves.easeInOut,
      child: AnimatedOpacity(
        opacity: 1,
        duration: const Duration(milliseconds: 300),
        child: _buildBanner(context, isOnline),
      ),
    );
  }

  Widget _buildBanner(BuildContext context, bool isOnline) {
    final message = isOnline ? 'Back online' : 'No internet connection';
    final icon = isOnline ? Icons.cloud_done : Icons.cloud_off;
    final backgroundColor = isOnline
        ? Colors.green.shade700
        : Theme.of(context).colorScheme.errorContainer;

    return Material(
      color: backgroundColor,
      elevation: 4,
      child: SafeArea(
        bottom: widget.position == OfflineIndicatorPosition.bottom,
        top: widget.position == OfflineIndicatorPosition.top,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(icon, color: Colors.white, size: 18),
              const SizedBox(width: 8),
              Text(
                message,
                style: AppTheme.caption(Colors.white).copyWith(
                  fontWeight: FontWeight.w500,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

/// Position of the offline indicator
enum OfflineIndicatorPosition {
  top,
  bottom,
}

/// Widget that temporarily shows its child and then fades out.
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
  double _opacity = 1.0;

  @override
  void initState() {
    super.initState();
    Future.delayed(widget.duration, () {
      if (mounted) {
        setState(() => _opacity = 0);
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedOpacity(
      opacity: _opacity,
      duration: const Duration(milliseconds: 400),
      curve: Curves.easeOut,
      child: _opacity > 0 ? widget.child : const SizedBox.shrink(),
    );
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
