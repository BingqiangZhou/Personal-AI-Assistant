import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/glass/glass_tokens.dart';

/// Text readability utility for glass surfaces.
///
/// Returns Apple label colors with alpha adjusted per glass tier.
/// Thinner glass tiers (light, medium) receive boosted alpha to
/// maintain text readability against more transparent backgrounds.
///
/// The alpha boosting follows Apple's approach for ensuring text
/// legibility on variable-transparency surfaces:
/// - **heavy/ultraHeavy**: Base alpha (full opacity background)
/// - **medium**: Base alpha + 0.1
/// - **light**: Base alpha + 0.15
///
/// Example:
/// ```dart
/// Text(
///   'Hello',
///   style: TextStyle(
///     color: GlassVibrancy.primaryText(context, tier: GlassTier.medium),
///   ),
/// )
/// ```
class GlassVibrancy {
  GlassVibrancy._();

  /// Primary text color for glass surfaces.
  ///
  /// Uses Apple's `.label` color with full opacity on all tiers.
  /// - Light mode: `#000000` (alpha 1.0)
  /// - Dark mode: `#FFFFFF` (alpha 1.0)
  static Color primaryText(BuildContext context, {required GlassTier tier}) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    // Apple .label: light=#000000, dark=#FFFFFF — full opacity always
    return isDark ? const Color(0xFFFFFFFF) : const Color(0xFF000000);
  }

  /// Secondary text color for glass surfaces.
  ///
  /// Uses Apple's `.secondaryLabel` color with alpha adjusted per tier.
  /// Base alpha is 0.6, boosted on lighter tiers:
  /// - heavy/ultraHeavy: 0.6 (base)
  /// - medium: 0.7 (boosted)
  /// - light: 0.75 (boosted)
  ///
  /// Light mode: `#3C3C43` with adjusted alpha
  /// Dark mode: `#EBEBF5` with adjusted alpha
  static Color secondaryText(BuildContext context, {required GlassTier tier}) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final baseAlpha = _boostedAlpha(0.6, tier);
    if (isDark) {
      return const Color(0xFFEBEBF5).withOpacity(baseAlpha);
    } else {
      return const Color(0xFF3C3C43).withOpacity(baseAlpha);
    }
  }

  /// Tertiary text color for glass surfaces.
  ///
  /// Uses Apple's `.tertiaryLabel` color with alpha adjusted per tier.
  /// Base alpha is 0.3, boosted on lighter tiers:
  /// - heavy/ultraHeavy: 0.3 (base)
  /// - medium: 0.45 (boosted)
  /// - light: 0.45 (boosted)
  ///
  /// Light mode: `#3C3C43` with adjusted alpha
  /// Dark mode: `#EBEBF5` with adjusted alpha
  static Color tertiaryText(BuildContext context, {required GlassTier tier}) {
    final isDark = Theme.of(context).brightness == Brightness.dark;
    final baseAlpha = _boostedAlphaTertiary(0.3, tier);
    if (isDark) {
      return const Color(0xFFEBEBF5).withOpacity(baseAlpha);
    } else {
      return const Color(0xFF3C3C43).withOpacity(baseAlpha);
    }
  }

  /// Boost alpha for thinner glass tiers to maintain readability.
  ///
  /// Returns the boosted alpha value (0.0-1.0) based on the glass tier:
  /// - ultraHeavy: baseAlpha (no boost)
  /// - heavy: baseAlpha (no boost)
  /// - medium: baseAlpha + 0.1 (clamped to 1.0)
  /// - light: baseAlpha + 0.15 (clamped to 1.0)
  static double _boostedAlpha(double baseAlpha, GlassTier tier) {
    return switch (tier) {
      GlassTier.ultraHeavy => baseAlpha,
      GlassTier.heavy => baseAlpha,
      GlassTier.medium => (baseAlpha + 0.1).clamp(0.0, 1.0),
      GlassTier.light => (baseAlpha + 0.15).clamp(0.0, 1.0),
    };
  }

  /// Boost alpha for tertiary text (same boost for light and medium).
  ///
  /// Returns the boosted alpha value (0.0-1.0) based on the glass tier:
  /// - ultraHeavy: baseAlpha (no boost)
  /// - heavy: baseAlpha (no boost)
  /// - medium: baseAlpha + 0.15 (clamped to 1.0)
  /// - light: baseAlpha + 0.15 (clamped to 1.0)
  static double _boostedAlphaTertiary(double baseAlpha, GlassTier tier) {
    return switch (tier) {
      GlassTier.ultraHeavy => baseAlpha,
      GlassTier.heavy => baseAlpha,
      GlassTier.medium => (baseAlpha + 0.15).clamp(0.0, 1.0),
      GlassTier.light => (baseAlpha + 0.15).clamp(0.0, 1.0),
    };
  }
}
