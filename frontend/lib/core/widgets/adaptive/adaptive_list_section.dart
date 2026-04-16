import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/platform/platform_helper.dart';

/// Adaptive list section container.
///
/// iOS: [CupertinoListSection.insetGrouped] with rounded corners and hairline dividers.
/// Android: Material [Card] with column layout.
class AdaptiveListSection extends StatelessWidget {
  const AdaptiveListSection({
    required this.children,
    super.key,
    this.header,
    this.footer,
    this.margin,
  });

  final String? header;
  final String? footer;
  final List<Widget> children;
  final EdgeInsetsGeometry? margin;

  @override
  Widget build(BuildContext context) {
    if (PlatformHelper.isIOS(context)) {
      return CupertinoListSection.insetGrouped(
        header: header != null ? Text(header!) : null,
        footer: footer != null ? Text(footer!) : null,
        margin: margin ??
            const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        children: children,
      );
    }

    final theme = Theme.of(context);
    return Card(
      margin: margin ?? const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (header != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
                child: Text(
                  header!,
                  style: theme.textTheme.labelSmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
            ...children,
            if (footer != null)
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 16, 12),
                child: Text(
                  footer!,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
