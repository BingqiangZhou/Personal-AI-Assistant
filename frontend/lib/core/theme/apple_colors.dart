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
  // ============================================================

  static const label = _AppleColorPair(
    light: Color(0xFF000000),
    dark: Color(0xFFFFFFFF),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const secondaryLabel = _AppleColorPair(
    light: Color(0xFF3C3C43),
    dark: Color(0xFFEBEBF5),
    lightAlpha: 0.6,
    darkAlpha: 0.6,
  );

  static const tertiaryLabel = _AppleColorPair(
    light: Color(0xFF3C3C43),
    dark: Color(0xFFEBEBF5),
    lightAlpha: 0.3,
    darkAlpha: 0.3,
  );

  // ============================================================
  // BACKGROUND COLORS
  // ============================================================

  static const systemGroupedBackground = _AppleColorPair(
    light: Color(0xFFF2F2F7),
    dark: Color(0xFF000000),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const secondarySystemGroupedBackground = _AppleColorPair(
    light: Color(0xFFFFFFFF),
    dark: Color(0xFF1C1C1E),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const tertiarySystemGroupedBackground = _AppleColorPair(
    light: Color(0xFFF2F2F7),
    dark: Color(0xFF2C2C2E),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  // ============================================================
  // FILL COLORS
  // ============================================================

  static const systemFill = _AppleColorPair(
    light: Color(0xFF787880),
    dark: Color(0xFF787880),
    lightAlpha: 0.2,
    darkAlpha: 0.36,
  );

  static const secondarySystemFill = _AppleColorPair(
    light: Color(0xFF787880),
    dark: Color(0xFF787880),
    lightAlpha: 0.16,
    darkAlpha: 0.32,
  );

  static const tertiarySystemFill = _AppleColorPair(
    light: Color(0xFF767680),
    dark: Color(0xFF767680),
    lightAlpha: 0.12,
    darkAlpha: 0.24,
  );

  // ============================================================
  // SEPARATOR COLOR
  // ============================================================

  static const separator = _AppleColorPair(
    light: Color(0xFF3C3C43),
    dark: Color(0xFF545458),
    lightAlpha: 0.29,
    darkAlpha: 0.6,
  );

  // ============================================================
  // SYSTEM TINT COLORS
  // ============================================================

  static const systemBlue = _AppleColorPair(
    light: Color(0xFF007AFF),
    dark: Color(0xFF0A84FF),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemGreen = _AppleColorPair(
    light: Color(0xFF34C759),
    dark: Color(0xFF30D158),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemIndigo = _AppleColorPair(
    light: Color(0xFF5856D6),
    dark: Color(0xFF5E5CE6),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemOrange = _AppleColorPair(
    light: Color(0xFFFF9500),
    dark: Color(0xFFFF9F0A),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemPink = _AppleColorPair(
    light: Color(0xFFFF2D55),
    dark: Color(0xFFFF375F),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemPurple = _AppleColorPair(
    light: Color(0xFFAF52DE),
    dark: Color(0xFFBF5AF2),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemRed = _AppleColorPair(
    light: Color(0xFFFF3B30),
    dark: Color(0xFFFF453A),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemYellow = _AppleColorPair(
    light: Color(0xFFFFCC00),
    dark: Color(0xFFFFD60A),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  static const systemTeal = _AppleColorPair(
    light: Color(0xFF5AC8FA),
    dark: Color(0xFF64D2FF),
    lightAlpha: 1.0,
    darkAlpha: 1.0,
  );

  // ============================================================
  // STATIC COLOR GETTERS (direct access, no BuildContext needed)
  // ============================================================

  static Color get systemIndigoLight => const Color(0xFF5856D6);
  static Color get systemIndigoDark => const Color(0xFF5E5CE6);
  static Color get systemOrangeLight => const Color(0xFFFF9500);
  static Color get systemOrangeDark => const Color(0xFFFF9F0A);
  static Color get systemPinkLight => const Color(0xFFFF2D55);
  static Color get systemPinkDark => const Color(0xFFFF375F);
  static Color get systemYellowLight => const Color(0xFFFFCC00);
  static Color get systemYellowDark => const Color(0xFFFFD60A);
  static Color get systemGreenLight => const Color(0xFF34C759);
  static Color get systemGreenDark => const Color(0xFF30D158);
  static Color get systemRedLight => const Color(0xFFFF3B30);
  static Color get systemRedDark => const Color(0xFFFF453A);
  static Color get systemBlueLight => const Color(0xFF007AFF);
  static Color get systemBlueDark => const Color(0xFF0A84FF);
  static Color get systemPurpleLight => const Color(0xFFAF52DE);
  static Color get systemPurpleDark => const Color(0xFFBF5AF2);
  static Color get systemTealLight => const Color(0xFF5AC8FA);
  static Color get systemTealDark => const Color(0xFF64D2FF);
}

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
  Color of(BuildContext context) {
    final brightness = Theme.of(context).brightness;
    final isDark = brightness == Brightness.dark;
    final baseColor = isDark ? dark : light;
    final alpha = isDark ? darkAlpha : lightAlpha;
    return baseColor.withOpacity(alpha);
  }
}
