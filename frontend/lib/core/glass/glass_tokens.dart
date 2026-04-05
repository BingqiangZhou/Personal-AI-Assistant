import 'package:flutter/material.dart';

/// Glass Tier System
///
/// Defines 4 tiers with specific blur sigma values for different use cases:
/// - ultraHeavy (30): Full-screen overlay, modal dialogs, expanded player
/// - heavy (24): Bottom sheets, large panels, sidebar
/// - medium (16): Navigation bar, tab bar, toolbar, search bar, mini player
/// - light (10): Cards, list items, small panels, buttons, chips
enum GlassTier {
  ultraHeavy(30),
  heavy(24),
  medium(16),
  light(10);

  final double sigma;
  const GlassTier(this.sigma);
}

/// Glass visual parameters for a specific tier and brightness.
///
/// Immutable class holding all visual parameters needed to render
/// the glass effect: fill colors, border colors, shadow, saturation,
/// and noise opacity.
@immutable
class GlassTierParams {
  const GlassTierParams({
    required this.fill,
    required this.borderTop,
    required this.borderBottom,
    required this.innerGlow,
    required this.shadow,
    required this.saturationBoost,
    required this.noiseOpacity,
    required this.contentScrim,
  });

  /// Semi-transparent fill color
  final Color fill;

  /// Top border gradient color (Fresnel edge light - bright)
  final Color borderTop;

  /// Bottom border gradient color (Fresnel edge light - dim)
  final Color borderBottom;

  /// Inner glow color (inset shadow)
  final Color innerGlow;

  /// Outer shadow color
  final Color shadow;

  /// Saturation boost factor for backdrop filter
  final double saturationBoost;

  /// Noise texture opacity
  final double noiseOpacity;

  /// Content scrim color — a tint layer placed under child content
  /// to guarantee text contrast against animated backgrounds.
  /// Combined with fill, provides the effective backing luminance.
  final Color contentScrim;
}

/// Glass Tokens
///
/// Immutable class holding all visual parameters per tier and brightness.
/// Provides static factory methods for dark/light modes and context-based
/// resolution.
@immutable
class GlassTokens {
  const GlassTokens({
    required this.brightness,
    required this.ultraHeavy,
    required this.heavy,
    required this.medium,
    required this.light,
  });

  final Brightness brightness;
  final GlassTierParams ultraHeavy;
  final GlassTierParams heavy;
  final GlassTierParams medium;
  final GlassTierParams light;

  /// Extract tokens from the current theme context
  static GlassTokens of(BuildContext context) {
    final themeBrightness = Theme.of(context).brightness;
    return themeBrightness == Brightness.dark
        ? const GlassTokens.dark()
        : const GlassTokens.light();
  }

  /// Dark mode tokens
  const factory GlassTokens.dark() = _DarkGlassTokens;

  /// Light mode tokens
  const factory GlassTokens.light() = _LightGlassTokens;

  /// Get params for a specific tier
  GlassTierParams paramsForTier(GlassTier tier) {
    return switch (tier) {
      GlassTier.ultraHeavy => ultraHeavy,
      GlassTier.heavy => heavy,
      GlassTier.medium => medium,
      GlassTier.light => light,
    };
  }

  /// Convenience getter for medium-tier fill color
  Color get glassFill => medium.fill;
}

/// Dark mode glass tokens
///
/// Design rationale: The dark background (#0A0A0F) is near-black.
/// Glass surfaces use white-tinted fills and scrims to create a
/// noticeably lighter surface that white/light text can contrast against.
///
/// Effective total opacity (fill ∘ scrim) per tier:
///   light:      ~35%  — enough for card/list item readability
///   medium:     ~43%  — nav bars, toolbars
///   heavy:      ~55%  — bottom sheets, sidebar
///   ultraHeavy: ~67%  — modals, full-screen overlays
class _DarkGlassTokens extends GlassTokens {
  const _DarkGlassTokens()
      : super(
          brightness: Brightness.dark,
          ultraHeavy: const GlassTierParams(
            fill: Color(0x47FFFFFF), // white 28%
            borderTop: Color(0x5CFFFFFF), // white 36%
            borderBottom: Color(0x40FFFFFF), // white 25%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x8C000000), // black 55%
            saturationBoost: 2.0,
            noiseOpacity: 0.06,
            contentScrim: Color(0x4CFFFFFF), // white 30%
          ),
          heavy: const GlassTierParams(
            fill: Color(0x3DFFFFFF), // white 24%
            borderTop: Color(0x52FFFFFF), // white 32%
            borderBottom: Color(0x35FFFFFF), // white 21%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x73000000), // black 45%
            saturationBoost: 1.8,
            noiseOpacity: 0.05,
            contentScrim: Color(0x38FFFFFF), // white 22%
          ),
          medium: const GlassTierParams(
            fill: Color(0x2EFFFFFF), // white 18%
            borderTop: Color(0x47FFFFFF), // white 28%
            borderBottom: Color(0x28FFFFFF), // white 16%
            innerGlow: Color(0x0DFFFFFF), // white 5%
            shadow: Color(0x59000000), // black 35%
            saturationBoost: 1.5,
            noiseOpacity: 0.04,
            contentScrim: Color(0x2DFFFFFF), // white 18%
          ),
          light: const GlassTierParams(
            fill: Color(0x24FFFFFF), // white 14%
            borderTop: Color(0x40FFFFFF), // white 25%
            borderBottom: Color(0x1EFFFFFF), // white 12%
            innerGlow: Color(0x0FFFFFFF), // white 6%
            shadow: Color(0x40000000), // black 25%
            saturationBoost: 1.3,
            noiseOpacity: 0.03,
            contentScrim: Color(0x24FFFFFF), // white 14%
          ),
        );
}

/// Light mode glass tokens
///
/// Design rationale: The light background (#F0F0F5) is near-white.
/// Glass surfaces use dark-tinted fills and scrims to create a
/// slightly darker surface that dark text can contrast against.
/// White fills would be invisible on light backgrounds, so we use
/// black tints for all fill/scrim layers.
///
/// Effective total opacity (fill ∘ scrim) per tier:
///   light:      ~18%  — subtle cards/list items
///   medium:     ~25%  — nav bars, toolbars
///   heavy:      ~35%  — bottom sheets, sidebar
///   ultraHeavy: ~46%  — modals, full-screen overlays
class _LightGlassTokens extends GlassTokens {
  const _LightGlassTokens()
      : super(
          brightness: Brightness.light,
          ultraHeavy: const GlassTierParams(
            fill: Color(0x38000000), // black 22%
            borderTop: Color(0x44000000), // black 27%
            borderBottom: Color(0x2C000000), // black 17%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x1F000000), // black 12%
            saturationBoost: 1.08,
            noiseOpacity: 0.04,
            contentScrim: Color(0x32000000), // black 20%
          ),
          heavy: const GlassTierParams(
            fill: Color(0x2C000000), // black 17%
            borderTop: Color(0x38000000), // black 22%
            borderBottom: Color(0x22000000), // black 13%
            innerGlow: Color(0x08FFFFFF), // white 3%
            shadow: Color(0x19000000), // black 10%
            saturationBoost: 1.06,
            noiseOpacity: 0.03,
            contentScrim: Color(0x26000000), // black 15%
          ),
          medium: const GlassTierParams(
            fill: Color(0x22000000), // black 13%
            borderTop: Color(0x2E000000), // black 18%
            borderBottom: Color(0x1A000000), // black 10%
            innerGlow: Color(0x06FFFFFF), // white 2.5%
            shadow: Color(0x14000000), // black 8%
            saturationBoost: 1.05,
            noiseOpacity: 0.03,
            contentScrim: Color(0x1E000000), // black 12%
          ),
          light: const GlassTierParams(
            fill: Color(0x1A000000), // black 10%
            borderTop: Color(0x28000000), // black 16%
            borderBottom: Color(0x13000000), // black 7.5%
            innerGlow: Color(0x05FFFFFF), // white 2%
            shadow: Color(0x0F000000), // black 6%
            saturationBoost: 1.03,
            noiseOpacity: 0.02,
            contentScrim: Color(0x15000000), // black 8%
          ),
        );
}
