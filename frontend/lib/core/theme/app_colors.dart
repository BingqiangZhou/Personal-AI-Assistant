import 'dart:ui' show lerpDouble;

import 'package:flutter/material.dart';

class AppColors {
  AppColors._();

  static const Color primary = Color(0xFF5CB8FF);
  static const Color riverAccent = Color(0xFF86F0FF);
  static const Color aqua = Color(0xFF8EE6FF);
  static const Color indigo = Color(0xFF7A8DFF);

  static const Color sunGlow = Color(0xFFFFD8A8);
  static const Color sunRay = Color(0xFFFF8A6B);
  static const Color leaf = Color(0xFF6EE7B7);
  static const Color mint = Color(0xFFB6F5D8);

  static const Color lightBackground = Color(0xFFF2F6FB);
  static const Color lightSurface = Color(0xFFFFFFFF);
  static const Color lightSurfaceVariant = Color(0xFFF8FBFF);
  static const Color lightOutline = Color(0xFFD6E3F2);
  static const Color lightTextPrimary = Color(0xFF0C1726);
  static const Color lightTextSecondary = Color(0xFF4B5C70);
  static const Color lightTextTertiary = Color(0xFF75859A);

  static const Color darkBackground = Color(0xFF06111D);
  static const Color darkSurface = Color(0xFF0D1927);
  static const Color darkSurfaceVariant = Color(0xFF132233);
  static const Color darkOutline = Color(0xFF2A3D54);
  static const Color darkTextPrimary = Color(0xFFF3F8FF);
  static const Color darkTextSecondary = Color(0xFFB8C8DA);
  static const Color darkTextTertiary = Color(0xFF8195AB);

  static const Color error = Color(0xFFFF6B72);
  static const Color success = Color(0xFF59D49A);
  static const Color warning = Color(0xFFFFB84D);
  static const Color info = primary;

  static const LinearGradient mindriverGradient = LinearGradient(
    colors: [Color(0xFFF6FBFF), Color(0xFFE5F3FF), Color(0xFFD7EDFF)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient softBackgroundGradient = LinearGradient(
    colors: [Color(0xFFF7FBFF), Color(0xFFEEF4FB), Color(0xFFE7EFF8)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient riverGradient = LinearGradient(
    colors: [Color(0xFF9BE8FF), Color(0xFF5CB8FF), Color(0xFF7A8DFF)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient sunsetGradient = LinearGradient(
    colors: [Color(0xFFFFD6A5), Color(0xFFFF9A76)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient natureGradient = LinearGradient(
    colors: [Color(0xFFC8F7E4), Color(0xFF6EE7B7)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient darkSubtleGradient = LinearGradient(
    colors: [Color(0xFF08111C), Color(0xFF0A1523), Color(0xFF102033)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient darkBrandGradient = LinearGradient(
    colors: [Color(0xFF0D1927), Color(0xFF10253A), Color(0xFF15314E)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );
}

@immutable
class MindriverThemeExtension extends ThemeExtension<MindriverThemeExtension> {
  const MindriverThemeExtension({
    required this.brandGradient,
    required this.riverGradient,
    required this.heroGradient,
    required this.shellGradient,
    required this.glassSurface,
    required this.glassSurfaceStrong,
    required this.glassBorder,
    required this.glassHighlight,
    required this.glassShadow,
    required this.heroGlow,
    required this.sunGlow,
    required this.sunRay,
    required this.leaf,
    required this.mint,
    required this.contentMaxWidth,
    required this.sectionGap,
    required this.cardRadius,
    required this.panelRadius,
    required this.navBackdropOpacity,
  });

  final Gradient brandGradient;
  final Gradient riverGradient;
  final Gradient heroGradient;
  final Gradient shellGradient;
  final Color glassSurface;
  final Color glassSurfaceStrong;
  final Color glassBorder;
  final Color glassHighlight;
  final Color glassShadow;
  final Color heroGlow;
  final Color sunGlow;
  final Color sunRay;
  final Color leaf;
  final Color mint;
  final double contentMaxWidth;
  final double sectionGap;
  final double cardRadius;
  final double panelRadius;
  final double navBackdropOpacity;

  @override
  MindriverThemeExtension copyWith({
    Gradient? brandGradient,
    Gradient? riverGradient,
    Gradient? heroGradient,
    Gradient? shellGradient,
    Color? glassSurface,
    Color? glassSurfaceStrong,
    Color? glassBorder,
    Color? glassHighlight,
    Color? glassShadow,
    Color? heroGlow,
    Color? sunGlow,
    Color? sunRay,
    Color? leaf,
    Color? mint,
    double? contentMaxWidth,
    double? sectionGap,
    double? cardRadius,
    double? panelRadius,
    double? navBackdropOpacity,
  }) {
    return MindriverThemeExtension(
      brandGradient: brandGradient ?? this.brandGradient,
      riverGradient: riverGradient ?? this.riverGradient,
      heroGradient: heroGradient ?? this.heroGradient,
      shellGradient: shellGradient ?? this.shellGradient,
      glassSurface: glassSurface ?? this.glassSurface,
      glassSurfaceStrong: glassSurfaceStrong ?? this.glassSurfaceStrong,
      glassBorder: glassBorder ?? this.glassBorder,
      glassHighlight: glassHighlight ?? this.glassHighlight,
      glassShadow: glassShadow ?? this.glassShadow,
      heroGlow: heroGlow ?? this.heroGlow,
      sunGlow: sunGlow ?? this.sunGlow,
      sunRay: sunRay ?? this.sunRay,
      leaf: leaf ?? this.leaf,
      mint: mint ?? this.mint,
      contentMaxWidth: contentMaxWidth ?? this.contentMaxWidth,
      sectionGap: sectionGap ?? this.sectionGap,
      cardRadius: cardRadius ?? this.cardRadius,
      panelRadius: panelRadius ?? this.panelRadius,
      navBackdropOpacity: navBackdropOpacity ?? this.navBackdropOpacity,
    );
  }

  @override
  MindriverThemeExtension lerp(
    ThemeExtension<MindriverThemeExtension>? other,
    double t,
  ) {
    if (other is! MindriverThemeExtension) {
      return this;
    }

    return MindriverThemeExtension(
      brandGradient: Gradient.lerp(brandGradient, other.brandGradient, t)!,
      riverGradient: Gradient.lerp(riverGradient, other.riverGradient, t)!,
      heroGradient: Gradient.lerp(heroGradient, other.heroGradient, t)!,
      shellGradient: Gradient.lerp(shellGradient, other.shellGradient, t)!,
      glassSurface: Color.lerp(glassSurface, other.glassSurface, t)!,
      glassSurfaceStrong: Color.lerp(
        glassSurfaceStrong,
        other.glassSurfaceStrong,
        t,
      )!,
      glassBorder: Color.lerp(glassBorder, other.glassBorder, t)!,
      glassHighlight: Color.lerp(glassHighlight, other.glassHighlight, t)!,
      glassShadow: Color.lerp(glassShadow, other.glassShadow, t)!,
      heroGlow: Color.lerp(heroGlow, other.heroGlow, t)!,
      sunGlow: Color.lerp(sunGlow, other.sunGlow, t)!,
      sunRay: Color.lerp(sunRay, other.sunRay, t)!,
      leaf: Color.lerp(leaf, other.leaf, t)!,
      mint: Color.lerp(mint, other.mint, t)!,
      contentMaxWidth: lerpDouble(contentMaxWidth, other.contentMaxWidth, t)!,
      sectionGap: lerpDouble(sectionGap, other.sectionGap, t)!,
      cardRadius: lerpDouble(cardRadius, other.cardRadius, t)!,
      panelRadius: lerpDouble(panelRadius, other.panelRadius, t)!,
      navBackdropOpacity: lerpDouble(
        navBackdropOpacity,
        other.navBackdropOpacity,
        t,
      )!,
    );
  }

  static const light = MindriverThemeExtension(
    brandGradient: AppColors.mindriverGradient,
    riverGradient: AppColors.riverGradient,
    heroGradient: LinearGradient(
      colors: [Color(0xFFEFF8FF), Color(0xFFE5F3FF), Color(0xFFF8FBFF)],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    shellGradient: AppColors.softBackgroundGradient,
    glassSurface: Color(0xCCFFFFFF),
    glassSurfaceStrong: Color(0xE6FFFFFF),
    glassBorder: Color(0x80D5E4F5),
    glassHighlight: Color(0xFFFFFFFF),
    glassShadow: Color(0x140C1726),
    heroGlow: Color(0x665CB8FF),
    sunGlow: AppColors.sunGlow,
    sunRay: AppColors.sunRay,
    leaf: AppColors.leaf,
    mint: AppColors.mint,
    contentMaxWidth: 1240,
    sectionGap: 20,
    cardRadius: 24,
    panelRadius: 28,
    navBackdropOpacity: 0.74,
  );

  static const dark = MindriverThemeExtension(
    brandGradient: AppColors.darkBrandGradient,
    riverGradient: AppColors.riverGradient,
    heroGradient: LinearGradient(
      colors: [Color(0xFF10253A), Color(0xFF0B1B2E), Color(0xFF12283F)],
      begin: Alignment.topLeft,
      end: Alignment.bottomRight,
    ),
    shellGradient: AppColors.darkSubtleGradient,
    glassSurface: Color(0xAA132233),
    glassSurfaceStrong: Color(0xCC102033),
    glassBorder: Color(0x66345068),
    glassHighlight: Color(0x33FFFFFF),
    glassShadow: Color(0x52000000),
    heroGlow: Color(0x445CB8FF),
    sunGlow: AppColors.sunGlow,
    sunRay: AppColors.sunRay,
    leaf: AppColors.leaf,
    mint: AppColors.mint,
    contentMaxWidth: 1240,
    sectionGap: 20,
    cardRadius: 24,
    panelRadius: 28,
    navBackdropOpacity: 0.68,
  );
}
