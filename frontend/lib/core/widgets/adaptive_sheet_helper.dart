import 'package:flutter/material.dart';

/// On desktop/tablet (width ≥ 600), shows a centered [Dialog] within the
/// current navigator's content area.  On mobile shows a standard
/// [showModalBottomSheet].
///
/// Returns the value produced by the builder (if any).
Future<T?> showAdaptiveSheet<T>({
  required BuildContext context,
  required Widget Function(BuildContext) builder,
  bool isScrollControlled = true,
  bool showDragHandle = true,
  bool useSafeArea = true,
  double desktopMaxWidth = 560,
  double desktopMaxHeightFraction = 0.85,
}) {
  final screenWidth = MediaQuery.of(context).size.width;

  if (screenWidth >= 600) {
    // Desktop / tablet → centred dialog scoped to the content area navigator.
    return showDialog<T>(
      context: context,
      useRootNavigator: false,
      barrierColor: Colors.black54,
      builder: (dialogCtx) {
        final size = MediaQuery.of(dialogCtx).size;
        return Center(
          child: ConstrainedBox(
            constraints: BoxConstraints(
              maxWidth: desktopMaxWidth,
              maxHeight: size.height * desktopMaxHeightFraction,
            ),
            child: Material(
              color: Theme.of(dialogCtx).colorScheme.surface,
              borderRadius: BorderRadius.circular(28),
              clipBehavior: Clip.antiAlias,
              elevation: 6,
              child: builder(dialogCtx),
            ),
          ),
        );
      },
    );
  }

  // Mobile → bottom sheet.
  return showModalBottomSheet<T>(
    context: context,
    isScrollControlled: isScrollControlled,
    showDragHandle: showDragHandle,
    useSafeArea: useSafeArea,
    useRootNavigator: false,
    backgroundColor: Theme.of(context).colorScheme.surface,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(28)),
    ),
    builder: builder,
  );
}
