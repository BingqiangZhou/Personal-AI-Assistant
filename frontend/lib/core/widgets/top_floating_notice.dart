import 'dart:async';

import 'package:flutter/material.dart';

OverlayEntry? _activeTopNoticeEntry;
Timer? _activeTopNoticeTimer;

void showTopFloatingNotice(
  BuildContext context, {
  required String message,
  bool isError = false,
  Duration duration = const Duration(seconds: 3),
  double extraTopOffset = 0,
}) {
  _removeTopFloatingNotice();

  final overlay = Overlay.maybeOf(context, rootOverlay: true);
  if (overlay == null) {
    return;
  }

  final callerScaffold = Scaffold.maybeOf(context);
  final callerAppBarHeight = callerScaffold?.widget.appBar?.preferredSize.height;

  final entry = OverlayEntry(
    builder: (overlayContext) {
      final theme = Theme.of(overlayContext);
      final isLight = theme.brightness == Brightness.light;
      final topInset =
          MediaQuery.maybeOf(overlayContext)?.viewPadding.top ?? 0;
      final scaffold = Scaffold.maybeOf(overlayContext);
      final appBarHeight =
          scaffold?.widget.appBar?.preferredSize.height ?? callerAppBarHeight;
      final effectiveTopBarHeight = appBarHeight ??
          ((scaffold == null && callerScaffold == null) ? kToolbarHeight : 0);
      final backgroundColor =
          isLight ? theme.colorScheme.surface : theme.colorScheme.primary;
      final foregroundColor = isError
          ? theme.colorScheme.error
          : (isLight ? Colors.black : Colors.white);
      final borderColor =
          isLight ? theme.colorScheme.outline : theme.colorScheme.onPrimary;
      final icon = isError ? Icons.error_outline : Icons.check_circle_outline;

      return Positioned(
        left: 16,
        right: 16,
        top: topInset + effectiveTopBarHeight + extraTopOffset + 12,
        child: IgnorePointer(
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 720),
              child: DecoratedBox(
                key: const Key('top_floating_notice'),
                decoration: BoxDecoration(
                  color: backgroundColor,
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: borderColor, width: 1),
                  boxShadow: const [
                    BoxShadow(
                      color: Color(0xFF101010),
                      blurRadius: 24,
                      offset: Offset(0, 12),
                    ),
                  ],
                ),
                child: Padding(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 14,
                    vertical: 12,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(icon, size: 18, color: foregroundColor),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          message,
                          key: const Key('top_floating_notice_message'),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                          style: theme.textTheme.bodyMedium?.copyWith(
                            color: foregroundColor,
                            fontSize: 14,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ),
        ),
      );
    },
  );

  _activeTopNoticeEntry = entry;
  overlay.insert(entry);
  _activeTopNoticeTimer = Timer(duration, _removeTopFloatingNotice);
}

void _removeTopFloatingNotice() {
  _activeTopNoticeTimer?.cancel();
  _activeTopNoticeTimer = null;

  _activeTopNoticeEntry?.remove();
  _activeTopNoticeEntry = null;
}
