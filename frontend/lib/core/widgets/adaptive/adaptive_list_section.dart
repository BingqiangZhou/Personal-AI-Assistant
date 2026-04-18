import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/constants/app_spacing.dart';
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
            EdgeInsets.symmetric(horizontal: context.spacing.md, vertical: context.spacing.sm),
        children: children,
      );
    }

    final theme = Theme.of(context);
    return Card(
      margin: margin ?? EdgeInsets.symmetric(horizontal: context.spacing.md, vertical: context.spacing.sm),
      child: Padding(
        padding: EdgeInsets.symmetric(vertical: context.spacing.xs),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (header != null)
              Padding(
                padding: EdgeInsets.fromLTRB(context.spacing.md, context.spacing.smMd, context.spacing.md, context.spacing.xs),
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
                padding: EdgeInsets.fromLTRB(context.spacing.md, context.spacing.xs, context.spacing.md, context.spacing.smMd),
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
