import 'package:flutter/material.dart';

/// Cosmic atmospheric background for Stella pages.
///
/// Adds subtle depth through gradient backgrounds:
/// - Dark: Deep indigo gradient (#0C0A1A → #16132B)
/// - Light: Warm white gradient (#FAFAFA → #F5F3FF)
///
/// Optionally renders faint radial glow points for star atmosphere.
class StellaBackground extends StatelessWidget {
  const StellaBackground({
    required this.child,
    this.enableGlow = false,
    super.key,
  });

  final Widget child;
  final bool enableGlow;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    return Container(
      decoration: BoxDecoration(
        gradient: isDark ? _darkGradient : _lightGradient,
      ),
      child: enableGlow ? _StarGlow(child: child) : child,
    );
  }

  static const _darkGradient = LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [
      Color(0xFF0C0A1A),
      Color(0xFF12102A),
      Color(0xFF16132B),
    ],
    stops: [0.0, 0.5, 1.0],
  );

  static const _lightGradient = LinearGradient(
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
    colors: [
      Color(0xFFFAFAFA),
      Color(0xFFF8F7FF),
      Color(0xFFF5F3FF),
    ],
    stops: [0.0, 0.5, 1.0],
  );
}

/// Subtle radial glow overlay — two very faint indigo "star" points.
class _StarGlow extends StatelessWidget {
  const _StarGlow({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) {
    final isDark = Theme.of(context).brightness == Brightness.dark;

    if (!isDark) return child; // Glow only visible in dark mode

    return Stack(
      children: [
        // Top-right star glow
        Positioned(
          top: -40,
          right: -20,
          child: Container(
            width: 200,
            height: 200,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(
                colors: [
                  const Color(0xFF6366F1).withValues(alpha: 0.08),
                  const Color(0xFF6366F1).withValues(alpha: 0),
                ],
              ),
            ),
          ),
        ),
        // Bottom-left star glow
        Positioned(
          bottom: 40,
          left: -60,
          child: Container(
            width: 280,
            height: 280,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(
                colors: [
                  const Color(0xFF6366F1).withValues(alpha: 0.05),
                  const Color(0xFF6366F1).withValues(alpha: 0),
                ],
              ),
            ),
          ),
        ),
        // Content
        child,
      ],
    );
  }
}
