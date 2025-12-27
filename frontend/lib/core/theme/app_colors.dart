import 'package:flutter/material.dart';

/// Mindriver Brand Color Tokens / Mindriver 品牌色彩标记
///
/// Complete color system for Light and Dark themes
/// 完整的亮色/暗色主题色彩系统
class AppColors {
  AppColors._();

  // ============================================================
  // BRAND COLORS / 品牌色
  // ============================================================

  /// Primary CTA color (Light theme) / 主要交互色（亮色主题）
  static const Color primary = Color(0xFF0070D0);

  /// River accent color / 河流强调色
  static const Color riverAccent = Color(0xFF43B5EC);

  /// Aqua color / 水绿色
  static const Color aqua = Color(0xFF77D8C5);

  /// Indigo color / 靛蓝色
  static const Color indigo = Color(0xFF5071B1);

  // ============================================================
  // ACCENT COLORS / 强调色
  // ============================================================

  /// Sun glow color / 阳光金色
  static const Color sunGlow = Color(0xFFF2E19E);

  /// Sun ray color / 阳光橙色
  static const Color sunRay = Color(0xFFE6A475);

  /// Leaf green color / 叶绿色
  static const Color leaf = Color(0xFF67B53D);

  /// Mint green color / 薄荷绿色
  static const Color mint = Color(0xFF74D597);

  // ============================================================
  // LIGHT THEME COLORS / 亮色主题颜色
  // ============================================================

  /// Light theme background / 亮色主题背景
  static const Color lightBackground = Color(0xFFF8F8F8);

  /// Light theme surface / 亮色主题表面
  static const Color lightSurface = Color(0xFFFFFFFF);

  /// Light theme surface variant / 亮色主题表面变体
  static const Color lightSurfaceVariant = Color(0xFFF0F0F8);

  /// Light theme outline / 亮色主题边框
  static const Color lightOutline = Color(0xFFD8E0F0);

  /// Light theme primary text / 亮色主题主要文字
  static const Color lightTextPrimary = Color(0xFF0B1A2A);

  /// Light theme secondary text / 亮色主题次要文字
  static const Color lightTextSecondary = Color(0xFF3A5268);

  /// Light theme tertiary text / 亮色主题第三级文字
  static const Color lightTextTertiary = Color(0xFF6B8094);

  // ============================================================
  // DARK THEME COLORS / 暗色主题颜色
  // ============================================================

  /// Dark theme background / 暗色主题背景
  static const Color darkBackground = Color(0xFF0B1020);

  /// Dark theme surface / 暗色主题表面
  static const Color darkSurface = Color(0xFF111A2E);

  /// Dark theme surface variant / 暗色主题表面变体
  static const Color darkSurfaceVariant = Color(0xFF17233B);

  /// Dark theme outline / 暗色主题边框
  static const Color darkOutline = Color(0xFF24314D);

  /// Dark theme primary text / 暗色主题主要文字
  static const Color darkTextPrimary = Color(0xFFEAF2FF);

  /// Dark theme secondary text / 暗色主题次要文字
  static const Color darkTextSecondary = Color(0xFFB6C6DA);

  /// Dark theme tertiary text / 暗色主题第三级文字
  static const Color darkTextTertiary = Color(0xFF7C8DA6);

  // ============================================================
  // SEMANTIC COLORS / 语义色
  // ============================================================

  /// Error color / 错误色
  static const Color error = Color(0xFFDC2626);

  /// Success color / 成功色 (using leaf)
  static const Color success = Color(0xFF67B53D);

  /// Warning color / 警告色
  static const Color warning = Color(0xFFF59E0B);

  /// Info color / 信息色
  static const Color info = Color(0xFF0070D0);

  // ============================================================
  // GRADIENTS / 渐变
  // ============================================================

  /// Main Mindriver brand gradient / Mindriver 品牌渐变
  static const LinearGradient mindriverGradient = LinearGradient(
    colors: [sunGlow, aqua, riverAccent, primary],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  /// Soft background gradient for light theme / 亮色主题柔和背景渐变
  static const LinearGradient softBackgroundGradient = LinearGradient(
    colors: [lightBackground, lightSurfaceVariant],
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
  );

  /// River gradient for accents / 河流强调渐变
  static const LinearGradient riverGradient = LinearGradient(
    colors: [aqua, riverAccent, primary],
    begin: Alignment(-1, -1),
    end: Alignment(1, 1),
  );

  /// Sunset gradient / 日落渐变
  static const LinearGradient sunsetGradient = LinearGradient(
    colors: [sunGlow, sunRay],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  /// Nature gradient / 自然渐变
  static const LinearGradient natureGradient = LinearGradient(
    colors: [mint, leaf],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  // ============================================================
  // DARK THEME GRADIENTS / 暗色主题渐变
  // ============================================================

  /// Dark theme subtle gradient / 暗色主题微妙渐变
  static const LinearGradient darkSubtleGradient = LinearGradient(
    colors: [darkBackground, darkSurfaceVariant],
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
  );

  /// Dark theme brand gradient / 暗色主题品牌渐变
  static const LinearGradient darkBrandGradient = LinearGradient(
    colors: [Color(0xFF1E3A5F), Color(0xFF0B2040)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );
}

/// Mindriver Theme Extension for additional custom tokens
/// Mindriver 主题扩展，用于额外的自定义标记
@immutable
class MindriverThemeExtension extends ThemeExtension<MindriverThemeExtension> {
  const MindriverThemeExtension({
    required this.brandGradient,
    required this.riverGradient,
    required this.sunsetGradient,
    required this.natureGradient,
    required this.sunGlow,
    required this.sunRay,
    required this.leaf,
    required this.mint,
  });

  /// Brand gradient / 品牌渐变
  final Gradient brandGradient;
  final Gradient riverGradient;
  final Gradient sunsetGradient;
  final Gradient natureGradient;

  /// Accent colors / 强调色
  final Color sunGlow;
  final Color sunRay;
  final Color leaf;
  final Color mint;

  @override
  MindriverThemeExtension copyWith({
    Gradient? brandGradient,
    Gradient? riverGradient,
    Gradient? sunsetGradient,
    Gradient? natureGradient,
    Color? sunGlow,
    Color? sunRay,
    Color? leaf,
    Color? mint,
  }) {
    return MindriverThemeExtension(
      brandGradient: brandGradient ?? this.brandGradient,
      riverGradient: riverGradient ?? this.riverGradient,
      sunsetGradient: sunsetGradient ?? this.sunsetGradient,
      natureGradient: natureGradient ?? this.natureGradient,
      sunGlow: sunGlow ?? this.sunGlow,
      sunRay: sunRay ?? this.sunRay,
      leaf: leaf ?? this.leaf,
      mint: mint ?? this.mint,
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
      sunsetGradient: Gradient.lerp(sunsetGradient, other.sunsetGradient, t)!,
      natureGradient: Gradient.lerp(natureGradient, other.natureGradient, t)!,
      sunGlow: Color.lerp(sunGlow, other.sunGlow, t)!,
      sunRay: Color.lerp(sunRay, other.sunRay, t)!,
      leaf: Color.lerp(leaf, other.leaf, t)!,
      mint: Color.lerp(mint, other.mint, t)!,
    );
  }

  /// Light theme extension / 亮色主题扩展
  static const light = MindriverThemeExtension(
    brandGradient: AppColors.mindriverGradient,
    riverGradient: AppColors.riverGradient,
    sunsetGradient: AppColors.sunsetGradient,
    natureGradient: AppColors.natureGradient,
    sunGlow: AppColors.sunGlow,
    sunRay: AppColors.sunRay,
    leaf: AppColors.leaf,
    mint: AppColors.mint,
  );

  /// Dark theme extension / 暗色主题扩展
  static const dark = MindriverThemeExtension(
    brandGradient: AppColors.darkBrandGradient,
    riverGradient: AppColors.riverGradient,
    sunsetGradient: AppColors.sunsetGradient,
    natureGradient: AppColors.natureGradient,
    sunGlow: AppColors.sunGlow,
    sunRay: AppColors.sunRay,
    leaf: AppColors.leaf,
    mint: AppColors.mint,
  );
}
