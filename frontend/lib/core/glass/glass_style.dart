import 'package:flutter/material.dart';

import 'package:personal_ai_assistant/core/glass/glass_tokens.dart';

/// Glass Style
///
/// Immutable data class holding all visual parameters for a single
/// glass instance. Created via factory for a tier, and can be modified
/// with hover/press states.
@immutable
class GlassStyle {
  const GlassStyle({
    required this.sigma,
    required this.fill,
    required this.borderTop,
    required this.borderBottom,
    required this.innerGlow,
    required this.shadow,
    required this.noiseOpacity,
    required this.saturationBoost,
    required this.contentScrim,
  });

  /// Blur sigma value
  final double sigma;

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

  /// Noise texture opacity
  final double noiseOpacity;

  /// Saturation boost factor for backdrop filter
  final double saturationBoost;

  /// Content scrim color — subtle tint layer under child content for text contrast
  final Color contentScrim;

  /// Create style for a specific tier and brightness
  factory GlassStyle.forTier(GlassTier tier, Brightness brightness) {
    final tokens = brightness == Brightness.dark
        ? const GlassTokens.dark()
        : const GlassTokens.light();
    final params = tokens.paramsForTier(tier);

    return GlassStyle(
      sigma: tier.sigma,
      fill: params.fill,
      borderTop: params.borderTop,
      borderBottom: params.borderBottom,
      innerGlow: params.innerGlow,
      shadow: params.shadow,
      noiseOpacity: params.noiseOpacity,
      saturationBoost: params.saturationBoost,
      contentScrim: params.contentScrim,
    );
  }

  /// Create hover state style: sigma+2, fill alpha+3%, border alpha x1.5, scrim alpha+2%
  GlassStyle withHover() {
    return GlassStyle(
      sigma: sigma + 2,
      fill: _addAlpha(fill, 0.03),
      borderTop: _scaleAlpha(borderTop, 1.5),
      borderBottom: _scaleAlpha(borderBottom, 1.5),
      innerGlow: innerGlow,
      shadow: shadow,
      noiseOpacity: noiseOpacity,
      saturationBoost: saturationBoost,
      contentScrim: _addAlpha(contentScrim, 0.02),
    );
  }

  /// Create press state style: sigma+4
  GlassStyle withPress() {
    return GlassStyle(
      sigma: sigma + 4,
      fill: fill,
      borderTop: borderTop,
      borderBottom: borderBottom,
      innerGlow: innerGlow,
      shadow: shadow,
      noiseOpacity: noiseOpacity,
      saturationBoost: saturationBoost,
      contentScrim: contentScrim,
    );
  }

  /// Copy with optional overrides
  GlassStyle copyWith({
    double? sigma,
    Color? fill,
    Color? borderTop,
    Color? borderBottom,
    Color? innerGlow,
    Color? shadow,
    double? noiseOpacity,
    double? saturationBoost,
    Color? contentScrim,
  }) {
    return GlassStyle(
      sigma: sigma ?? this.sigma,
      fill: fill ?? this.fill,
      borderTop: borderTop ?? this.borderTop,
      borderBottom: borderBottom ?? this.borderBottom,
      innerGlow: innerGlow ?? this.innerGlow,
      shadow: shadow ?? this.shadow,
      noiseOpacity: noiseOpacity ?? this.noiseOpacity,
      saturationBoost: saturationBoost ?? this.saturationBoost,
      contentScrim: contentScrim ?? this.contentScrim,
    );
  }

  /// Add to alpha channel (0.0 to 1.0)
  Color _addAlpha(Color color, double delta) {
    final newAlpha = (color.alpha / 255 + delta).clamp(0.0, 1.0);
    return color.withValues(alpha: newAlpha);
  }

  /// Scale alpha channel by multiplier
  Color _scaleAlpha(Color color, double multiplier) {
    final newAlpha = (color.alpha / 255 * multiplier).clamp(0.0, 1.0);
    return color.withValues(alpha: newAlpha);
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    return other is GlassStyle &&
        other.sigma == sigma &&
        other.fill == fill &&
        other.borderTop == borderTop &&
        other.borderBottom == borderBottom &&
        other.innerGlow == innerGlow &&
        other.shadow == shadow &&
        other.noiseOpacity == noiseOpacity &&
        other.saturationBoost == saturationBoost &&
        other.contentScrim == contentScrim;
  }

  @override
  int get hashCode {
    return Object.hash(
      sigma,
      fill,
      borderTop,
      borderBottom,
      innerGlow,
      shadow,
      noiseOpacity,
      saturationBoost,
      contentScrim,
    );
  }
}
