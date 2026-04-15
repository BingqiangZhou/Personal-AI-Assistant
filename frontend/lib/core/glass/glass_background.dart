import 'package:flutter/material.dart';

/// Glass Background Theme
///
/// Defines the color palette for gradient orbs based on context.
/// All themes now use identical gray orb colors for monochrome glass aesthetic.
enum GlassBackgroundTheme {
  podcast,
  home,
  neutral,
}

/// Glass Background
///
/// Background with neutral base color and 4 static gradient orbs
/// providing subtle atmospheric depth.
/// Includes RepaintBoundary for performance and respects disableAnimations.
class GlassBackground extends StatelessWidget {
  const GlassBackground({
    required this.child,
    this.theme = GlassBackgroundTheme.podcast,
    this.enableAnimation = false,
    super.key,
  });

  final Widget child;
  final GlassBackgroundTheme theme;
  final bool enableAnimation;

  // Orb configuration
  static const int _orbCount = 4;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final disableAnimations = MediaQuery.disableAnimationsOf(context);

    return RepaintBoundary(
      child: Container(
        decoration: BoxDecoration(
          color: isDark ? const Color(0xFF0f0f1a) : const Color(0xFFF8F9FA),
        ),
        child: Stack(
          children: [
            // Gradient orbs (only when animations are enabled)
            if (!disableAnimations) ..._buildOrbs(isDark),
            // Content
            child,
          ],
        ),
      ),
    );
  }

  /// Build static gradient orbs at fixed positions
  List<Widget> _buildOrbs(bool isDark) {
    final colors = _getThemeColors(isDark);
    final opacity = isDark ? 0.06 : 0.15;

    return List.generate(_orbCount, (index) {
      return Positioned(
        left: 100.0 * index,
        top: 100.0 * index,
        child: Container(
          width: 200,
          height: 200,
          decoration: BoxDecoration(
            shape: BoxShape.circle,
            gradient: RadialGradient(
              colors: [
                colors[index % colors.length].withValues(alpha: opacity),
                colors[index % colors.length].withValues(alpha: 0),
              ],
            ),
          ),
        ),
      );
    });
  }

  /// Get theme colors for gradient orbs
  List<Color> _getThemeColors(bool isDark) {
    if (isDark) {
      // Deep, desaturated colors that blend into #0f0f1a background
      return const [
        Color(0xFF1a1a24), // cool gray
        Color(0xFF181818), // neutral gray
        Color(0xFF1c1c20), // blue-gray
      ];
    }

    switch (theme) {
      case GlassBackgroundTheme.podcast:
        return const [
          Color(0xFFe0e0e0),
          Color(0xFFd8d8dc),
          Color(0xFFe4e4e4),
        ];
      case GlassBackgroundTheme.home:
        return const [
          Color(0xFFe0e0e0),
          Color(0xFFd8d8dc),
          Color(0xFFe4e4e4),
        ];
      case GlassBackgroundTheme.neutral:
        return const [
          Color(0xFFe0e0e0),
          Color(0xFFd8d8dc),
          Color(0xFFe4e4e4),
        ];
    }
  }
}
