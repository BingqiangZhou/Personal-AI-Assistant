import 'package:flutter/material.dart';

/// Surface card variants for different visual hierarchy levels.
enum SurfaceCardVariant {
  /// Standard card with secondarySystemGroupedBackground.
  normal,

  /// Elevated card (same as normal, can add shadow later).
  elevated,

  /// Flat card with tertiarySystemGroupedBackground.
  flat,
}

/// A content layer card widget using Apple HIG system colors.
///
/// Provides a card surface with proper background colors and borders
/// following Apple's Human Interface Guidelines. The card automatically
/// adapts to light/dark mode and supports three variants:
///
/// - **normal**: Uses `secondarySystemGroupedBackground` (white/light gray)
/// - **elevated**: Same as normal (prepared for future shadow support)
/// - **flat**: Uses `tertiarySystemGroupedBackground` (lighter/darker gray)
///
/// The border color uses Apple's `tertiarySystemFill` with proper opacity.
///
/// Example:
/// ```dart
/// SurfaceCard(
///   padding: const EdgeInsets.all(16),
///   child: Text('Content'),
/// )
/// ```
class SurfaceCard extends StatelessWidget {
  /// Creates a surface card.
  const SurfaceCard({
    super.key,
    required this.child,
    this.padding,
    this.borderRadius = 16,
    this.variant = SurfaceCardVariant.normal,
    this.backgroundColor,
  });

  /// The content widget inside the card.
  final Widget child;

  /// Optional padding around the child.
  final EdgeInsetsGeometry? padding;

  /// The border radius of the card.
  final double borderRadius;

  /// The visual variant of the card.
  final SurfaceCardVariant variant;

  /// Optional custom background color.
  /// When provided, this overrides the variant-based background color.
  final Color? backgroundColor;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    // Background colors from Apple HIG systemGroupedBackground
    final Color bg;
    if (backgroundColor != null) {
      bg = backgroundColor!;
    } else {
      bg = switch (variant) {
        SurfaceCardVariant.normal => isDark
            ? const Color(0xFF1C1C1E) // secondarySystemGroupedBackground dark
            : const Color(0xFFFFFFFF), // secondarySystemGroupedBackground light
        SurfaceCardVariant.elevated => isDark
            ? const Color(0xFF1C1C1E) // secondarySystemGroupedBackground dark
            : const Color(0xFFFFFFFF), // secondarySystemGroupedBackground light
        SurfaceCardVariant.flat => isDark
            ? const Color(0xFF2C2C2E) // tertiarySystemGroupedBackground dark
            : const Color(0xFFF2F2F7), // tertiarySystemGroupedBackground light
      };
    }

    // Border from Apple HIG tertiarySystemFill
    // Base color: #767680 with opacity
    // Light mode: 12% opacity, Dark mode: 24% opacity
    final borderColor = isDark
        ? const Color(0x3D767680) // 24% opacity
        : const Color(0x1E767680); // 12% opacity

    return Container(
      decoration: BoxDecoration(
        color: bg,
        borderRadius: BorderRadius.circular(borderRadius),
        border: Border.all(
          color: borderColor,
          width: 1,
        ),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(borderRadius),
        child: padding != null
            ? Padding(padding: padding!, child: child)
            : child,
      ),
    );
  }
}
