import 'package:flutter/material.dart';

/// Apple Human Interface Guidelines (HIG) System Colors
///
/// Provides static access to all Apple HIG color values with
/// theme-aware resolution via the `of(BuildContext)` method.
///
/// Colors are provided in pairs for light and dark modes.
/// The `.light` and `.dark` properties return the base color values
/// (at full opacity).
/// The `of()` method applies the appropriate alpha based on the
/// color's semantic meaning and current brightness.
///
/// Reference:
/// https://developer.apple.com/design/human-interface-guidelines/color
class AppleColors {
  AppleColors._();

  // ============================================================
  // LABEL COLORS
  // Text colors for labels and content.
  // ============================================================

  /// Primary label color.
  /// Full opacity for primary text.
  static const _AppleColorPair label = _AppleColorPair(
    light: Color(0xFF000000),
    dark: Color(0xFFFFFFFF),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// Secondary label color.
  /// Base color at full opacity; use `of()` for 60% opacity.
  static const _AppleColorPair secondaryLabel = _AppleColorPair(
    light: Color(0xFF3C3C43),
    dark: Color(0xFFEBEBF5),
    lightAlpha: 0.6,
    darkAlpha: 0.6,
  );

  /// Tertiary label color.
  /// Base color at full opacity; use `of()` for 30% opacity.
  static const _AppleColorPair tertiaryLabel = _AppleColorPair(
    light: Color(0xFF3C3C43),
    dark: Color(0xFFEBEBF5),
    lightAlpha: 0.3,
    darkAlpha: 0.3,
  );

  // ============================================================
  // BACKGROUND COLORS
  // Colors for grouped backgrounds.
  // ============================================================

  /// System grouped background color.
  /// Main background for grouped content.
  static const _AppleColorPair systemGroupedBackground = _AppleColorPair(
    light: Color(0xFFF2F2F7),
    dark: Color(0xFF000000),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// Secondary system grouped background color.
  /// Background for grouped content sections.
  static const _AppleColorPair secondarySystemGroupedBackground =
      _AppleColorPair(
    light: Color(0xFFFFFFFF),
    dark: Color(0xFF1C1C1E),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// Tertiary system grouped background color.
  /// Background for nested grouped content.
  static const _AppleColorPair tertiarySystemGroupedBackground =
      _AppleColorPair(
    light: Color(0xFFF2F2F7),
    dark: Color(0xFF2C2C2E),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  // ============================================================
  // FILL COLORS
  // Semi-transparent fill colors for UI elements.
  // ============================================================

  /// System fill color.
  /// 20% opacity (light) / 36% opacity (dark).
  static const _AppleColorPair systemFill = _AppleColorPair(
    light: Color(0xFF787880),
    dark: Color(0xFF787880),
    lightAlpha: 0.2,
    darkAlpha: 0.36,
  );

  /// Secondary system fill color.
  /// 16% opacity (light) / 32% opacity (dark).
  static const _AppleColorPair secondarySystemFill = _AppleColorPair(
    light: Color(0xFF787880),
    dark: Color(0xFF787880),
    lightAlpha: 0.16,
    darkAlpha: 0.32,
  );

  /// Tertiary system fill color.
  /// 12% opacity (light) / 24% opacity (dark).
  static const _AppleColorPair tertiarySystemFill = _AppleColorPair(
    light: Color(0xFF767680),
    dark: Color(0xFF767680),
    lightAlpha: 0.12,
    darkAlpha: 0.24,
  );

  // ============================================================
  // SEPARATOR COLOR
  // Color for separators and borders.
  // ============================================================

  /// Separator color.
  /// 29% opacity (light) / 60% opacity (dark).
  static const _AppleColorPair separator = _AppleColorPair(
    light: Color(0xFF3C3C43),
    dark: Color(0xFF545458),
    lightAlpha: 0.29,
    darkAlpha: 0.6,
  );

  // ============================================================
  // SYSTEM TINT COLORS
  // Accent colors for UI elements.
  // ============================================================

  /// System blue color.
  static const _AppleColorPair systemBlue = _AppleColorPair(
    light: Color(0xFF007AFF),
    dark: Color(0xFF0A84FF),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System green color.
  static const _AppleColorPair systemGreen = _AppleColorPair(
    light: Color(0xFF34C759),
    dark: Color(0xFF30D158),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System indigo color.
  static const _AppleColorPair systemIndigo = _AppleColorPair(
    light: Color(0xFF5856D6),
    dark: Color(0xFF5E5CE6),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System orange color.
  static const _AppleColorPair systemOrange = _AppleColorPair(
    light: Color(0xFFFF9500),
    dark: Color(0xFFFF9F0A),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System pink color.
  static const _AppleColorPair systemPink = _AppleColorPair(
    light: Color(0xFFFF2D55),
    dark: Color(0xFFFF375F),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System purple color.
  static const _AppleColorPair systemPurple = _AppleColorPair(
    light: Color(0xFFAF52DE),
    dark: Color(0xFFBF5AF2),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System red color.
  static const _AppleColorPair systemRed = _AppleColorPair(
    light: Color(0xFFFF3B30),
    dark: Color(0xFFFF453A),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System yellow color.
  static const _AppleColorPair systemYellow = _AppleColorPair(
    light: Color(0xFFFFCC00),
    dark: Color(0xFFFFD60A),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  /// System teal color.
  static const _AppleColorPair systemTeal = _AppleColorPair(
    light: Color(0xFF5AC8FA),
    dark: Color(0xFF64D2FF),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );
}

/// Internal class representing a color pair for light/dark modes.
@immutable
class _AppleColorPair {
  const _AppleColorPair({
    required this.light,
    required this.dark,
    required this.lightAlpha,
    required this.darkAlpha,
  });

  final Color light;
  final Color dark;
  final double lightAlpha;
  final double darkAlpha;

  /// Resolve the appropriate color based on the current theme brightness.
  /// Applies the appropriate alpha for the brightness mode.
  Color of(BuildContext context) {
    final brightness = Theme.of(context).brightness;
    final isDark = brightness == Brightness.dark;
    final baseColor = isDark ? dark : light;
    final alpha = isDark ? darkAlpha : lightAlpha;
    return baseColor.withOpacity(alpha);
  }
}
