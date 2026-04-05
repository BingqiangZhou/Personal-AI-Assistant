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
/// Apple Liquid Glass alignment: White-tinted glass on pure #000000 background.
/// Consistent 40% top border (Fresnel edge), 10% bottom border across all tiers.
/// Uniform saturation boost (1.8) and inner glow (4% white) for consistency.
///
/// Effective total opacity (fill + scrim) per tier:
///   light:      ~13%  — subtle cards, list items, small panels
///   medium:     ~18%  — nav bars, toolbars, search bars, mini player
///   heavy:      ~24%  — bottom sheets, sidebar, large panels
///   ultraHeavy: ~30%  — modals, full-screen overlays, expanded player
class _DarkGlassTokens extends GlassTokens {
  const _DarkGlassTokens()
      : super(
          brightness: Brightness.dark,
          ultraHeavy: const GlassTierParams(
            fill: Color(0x1AFFFFFF), // white 10%
            borderTop: Color(0x66FFFFFF), // white 40%
            borderBottom: Color(0x1AFFFFFF), // white 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x1F000000), // black 12%
            saturationBoost: 1.8,
            noiseOpacity: 0.04,
            contentScrim: Color(0x33FFFFFF), // white 20%
          ),
          heavy: const GlassTierParams(
            fill: Color(0x14FFFFFF), // white 8%
            borderTop: Color(0x66FFFFFF), // white 40%
            borderBottom: Color(0x1AFFFFFF), // white 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x19000000), // black 10%
            saturationBoost: 1.8,
            noiseOpacity: 0.03,
            contentScrim: Color(0x29FFFFFF), // white 16%
          ),
          medium: const GlassTierParams(
            fill: Color(0x0FFFFFFF), // white 6%
            borderTop: Color(0x66FFFFFF), // white 40%
            borderBottom: Color(0x1AFFFFFF), // white 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x14000000), // black 8%
            saturationBoost: 1.8,
            noiseOpacity: 0.03,
            contentScrim: Color(0x1FFFFFFF), // white 12%
          ),
          light: const GlassTierParams(
            fill: Color(0x0DFFFFFF), // white 5%
            borderTop: Color(0x66FFFFFF), // white 40%
            borderBottom: Color(0x1AFFFFFF), // white 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x0F000000), // black 6%
            saturationBoost: 1.8,
            noiseOpacity: 0.03,
            contentScrim: Color(0x14FFFFFF), // white 8%
          ),
        );
}

/// Light mode glass tokens
///
/// Apple Liquid Glass alignment: Black-tinted glass on #F2F2F7 background.
/// Consistent 40% top border (Fresnel edge), 10% bottom border across all tiers.
/// Uniform saturation boost (1.8) and inner glow (4% white) for consistency.
///
/// Effective total opacity (fill + scrim) per tier:
///   light:      ~8%   — subtle cards, list items, small panels
///   medium:     ~13%  — nav bars, toolbars, search bars, mini player
///   heavy:      ~18%  — bottom sheets, sidebar, large panels
///   ultraHeavy: ~23%  — modals, full-screen overlays, expanded player
class _LightGlassTokens extends GlassTokens {
  const _LightGlassTokens()
      : super(
          brightness: Brightness.light,
          ultraHeavy: const GlassTierParams(
            fill: Color(0x14000000), // black 8%
            borderTop: Color(0x66000000), // black 40%
            borderBottom: Color(0x1A000000), // black 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x1F000000), // black 12%
            saturationBoost: 1.8,
            noiseOpacity: 0.04,
            contentScrim: Color(0x26000000), // black 15%
          ),
          heavy: const GlassTierParams(
            fill: Color(0x0F000000), // black 6%
            borderTop: Color(0x66000000), // black 40%
            borderBottom: Color(0x1A000000), // black 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x19000000), // black 10%
            saturationBoost: 1.8,
            noiseOpacity: 0.03,
            contentScrim: Color(0x1F000000), // black 12%
          ),
          medium: const GlassTierParams(
            fill: Color(0x0D000000), // black 5%
            borderTop: Color(0x66000000), // black 40%
            borderBottom: Color(0x1A000000), // black 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x14000000), // black 8%
            saturationBoost: 1.8,
            noiseOpacity: 0.03,
            contentScrim: Color(0x14000000), // black 8%
          ),
          light: const GlassTierParams(
            fill: Color(0x08000000), // black 3%
            borderTop: Color(0x66000000), // black 40%
            borderBottom: Color(0x1A000000), // black 10%
            innerGlow: Color(0x0AFFFFFF), // white 4%
            shadow: Color(0x0F000000), // black 6%
            saturationBoost: 1.8,
            noiseOpacity: 0.03,
            contentScrim: Color(0x0D000000), // black 5%
          ),
        );
}
