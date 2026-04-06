import 'package:flutter/material.dart';

/// A Linear-style section header with title and optional trailing widget.
///
/// Features:
/// - 48px display title (adjustable)
/// - Optional subtitle with reduced opacity
/// - Optional trailing widget (e.g., button, icon)
/// - Consistent vertical spacing
class LinearSectionHeader extends StatelessWidget {
  const LinearSectionHeader({
    super.key,
    required this.title,
    this.subtitle,
    this.trailing,
    this.titleSize = 48,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
  });

  final String title;
  final String? subtitle;
  final Widget? trailing;
  final double titleSize;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return Padding(
      padding: padding,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.baseline,
        textBaseline: TextBaseline.alphabetic,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  title,
                  style: theme.textTheme.displaySmall?.copyWith(
                    fontSize: titleSize,
                    fontWeight: FontWeight.w800,
                    color: scheme.onSurface,
                    height: 1.2,
                  ),
                ),
                if (subtitle != null) ...[
                  const SizedBox(height: 4),
                  Text(
                    subtitle!,
                    style: theme.textTheme.titleMedium?.copyWith(
                      color: scheme.onSurfaceVariant,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ],
            ),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}

/// A smaller Linear-style section header for subsections.
///
/// Features:
/// - 24px title (adjustable)
/// - Optional leading icon
/// - Optional trailing widget
/// - Compact padding
class LinearSubsectionHeader extends StatelessWidget {
  const LinearSubsectionHeader({
    super.key,
    required this.title,
    this.leading,
    this.trailing,
    this.titleSize = 24,
    this.padding = const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
  });

  final String title;
  final Widget? leading;
  final Widget? trailing;
  final double titleSize;
  final EdgeInsetsGeometry padding;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final scheme = theme.colorScheme;

    return Padding(
      padding: padding,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          if (leading != null) ...[
            leading!,
            const SizedBox(width: 12),
          ],
          Expanded(
            child: Text(
              title,
              style: theme.textTheme.titleLarge?.copyWith(
                fontSize: titleSize,
                fontWeight: FontWeight.w700,
                color: scheme.onSurface,
              ),
            ),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}
