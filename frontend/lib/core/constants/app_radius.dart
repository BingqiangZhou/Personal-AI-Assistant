import 'package:flutter/material.dart';

import 'package:personal_ai_assistant/core/theme/app_colors.dart';

/// ============================================================
/// Arctic Garden Design System - 形状与圆角系统
///
/// Design Philosophy:
/// - 有机形态：使用更大的圆角，避免尖锐的边角
/// - 柔和曲线：所有形状都应该感觉自然、流畅
/// ============================================================

/// Design tokens for border radius throughout the app.
///
/// Values are aligned with [AppThemeExtension] as the single source of truth.
/// Use the pre-built [BorderRadius] and [RoundedRectangleBorder] getters
/// for convenience, or access [AppThemeExtension] directly for theme-aware values.
class AppRadius {
  AppRadius._();

  // ============================================================
  // CORE RADIUS VALUES — aligned with AppThemeExtension
  // ============================================================

  static const double cardValue = 12.0;
  static const double panelValue = 16.0;
  static const double buttonValue = 10.0;

  // Incremental scale
  static const double xs = 6.0;
  static const double sm = 8.0;
  static const double md = 10.0;
  static const double lg = 14.0;
  static const double xl = 20.0;
  static const double xxl = 28.0;
  static const double pill = 999.0;

  // ============================================================
  // PRE-BUILT BORDER RADIUS INSTANCES - 预构建圆角实例
  // ============================================================

  static BorderRadius get xsRadius => BorderRadius.circular(xs);
  static BorderRadius get smRadius => BorderRadius.circular(sm);
  static BorderRadius get mdRadius => BorderRadius.circular(md);
  static BorderRadius get lgRadius => BorderRadius.circular(lg);
  static BorderRadius get xlRadius => BorderRadius.circular(xl);
  static BorderRadius get xxlRadius => BorderRadius.circular(xxl);
  static BorderRadius get card => BorderRadius.circular(cardValue);
  static BorderRadius get panel => BorderRadius.circular(panelValue);
  static BorderRadius get button => BorderRadius.circular(buttonValue);
  static BorderRadius get pillRadius => BorderRadius.circular(pill);

  // ============================================================
  // ORGANIC SHAPES - 有机形状（不对称圆角）
  // ============================================================

  /// 有机卡片形状 - 左上角稍大，更有动感
  static BorderRadius get organicCard => const BorderRadius.only(
    topLeft: Radius.circular(24),
    topRight: Radius.circular(20),
    bottomLeft: Radius.circular(20),
    bottomRight: Radius.circular(16),
  );

  /// 有机按钮形状 - 更圆润
  static BorderRadius get organicButton => BorderRadius.horizontal(
    left: const Radius.circular(20),
    right: const Radius.circular(14),
  );

  // ============================================================
  // ROUNDED RECTANGLE BORDER SHAPES - 预构建形状
  // ============================================================

  static RoundedRectangleBorder get xsShape =>
      RoundedRectangleBorder(borderRadius: xsRadius);
  static RoundedRectangleBorder get smShape =>
      RoundedRectangleBorder(borderRadius: smRadius);
  static RoundedRectangleBorder get mdShape =>
      RoundedRectangleBorder(borderRadius: mdRadius);
  static RoundedRectangleBorder get lgShape =>
      RoundedRectangleBorder(borderRadius: lgRadius);
  static RoundedRectangleBorder get xlShape =>
      RoundedRectangleBorder(borderRadius: xlRadius);
  static RoundedRectangleBorder get xxlShape =>
      RoundedRectangleBorder(borderRadius: xxlRadius);
  static RoundedRectangleBorder get cardShape =>
      RoundedRectangleBorder(borderRadius: card);
  static RoundedRectangleBorder get panelShape =>
      RoundedRectangleBorder(borderRadius: panel);
  static RoundedRectangleBorder get buttonShape =>
      RoundedRectangleBorder(borderRadius: button);
  static RoundedRectangleBorder get pillShape =>
      RoundedRectangleBorder(borderRadius: pillRadius);
  static RoundedRectangleBorder get organicCardShape =>
      RoundedRectangleBorder(borderRadius: organicCard);
}

/// Extension to easily access radius from BuildContext.
extension AppRadiusExtension on BuildContext {
  /// Get the card radius from the current theme.
  double get cardRadius {
    final extension =
        Theme.of(this).extension<AppThemeExtension>();
    return extension?.cardRadius ?? AppRadius.cardValue;
  }

  /// Get the panel radius from the current theme.
  double get panelRadius {
    final extension =
        Theme.of(this).extension<AppThemeExtension>();
    return extension?.panelRadius ?? AppRadius.panelValue;
  }
}
