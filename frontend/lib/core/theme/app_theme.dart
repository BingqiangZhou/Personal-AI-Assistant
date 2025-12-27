import 'package:flutter/material.dart';
import '../constants/breakpoints.dart';
import 'mindriver_theme.dart';
import 'app_colors.dart';

/// AppTheme - Main theme accessor
/// AppTheme - 主主题访问器
///
/// This class wraps the MindriverTheme for backward compatibility
/// 此类包装 MindriverTheme 以保持向后兼容性
class AppTheme {
  AppTheme._();

  // ============================================================
  // LEGACY COLOR CONSTANTS (for backward compatibility)
  // 向后兼容的遗留颜色常量
  // ============================================================

  static const Color primaryColor = AppColors.primary;
  static const Color primaryDarkColor = AppColors.riverAccent;
  static const Color secondaryColor = AppColors.indigo;
  static const Color accentColor = AppColors.riverAccent;

  static const Color surfaceColor = AppColors.lightSurface;
  static const Color cardColor = AppColors.lightSurface;

  static const Color textPrimary = AppColors.lightTextPrimary;
  static const Color textSecondary = AppColors.lightTextSecondary;
  static const Color textTertiary = AppColors.lightTextTertiary;

  static const Color errorColor = AppColors.error;
  static const Color warningColor = AppColors.warning;
  static const Color successColor = AppColors.success;
  static const Color infoColor = AppColors.info;

  static const Color dividerColor = AppColors.lightOutline;
  static const Color borderColor = AppColors.lightOutline;

  // Dark theme colors / 暗色主题颜色
  static const Color darkSurfaceColor = AppColors.darkSurface;
  static const Color darkCardColor = AppColors.darkSurfaceVariant;

  static const Color darkTextPrimary = AppColors.darkTextPrimary;
  static const Color darkTextSecondary = AppColors.darkTextSecondary;
  static const Color darkTextTertiary = AppColors.darkTextTertiary;

  static const Color darkDividerColor = AppColors.darkOutline;
  static const Color darkBorderColor = AppColors.darkOutline;

  // ============================================================
  // RESPONSIVE HELPERS / 响应式助手
  // ============================================================

  /// 响应式边距助手
  static EdgeInsetsGeometry getResponsivePadding(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return const EdgeInsets.all(16.0); // 移动端
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return const EdgeInsets.all(24.0); // 平板端
    } else {
      return const EdgeInsets.all(32.0); // 桌面端
    }
  }

  /// 响应式水平边距助手
  static EdgeInsetsGeometry getResponsiveHorizontalPadding(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return const EdgeInsets.symmetric(horizontal: 16.0); // 移动端
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return const EdgeInsets.symmetric(horizontal: 24.0); // 平板端
    } else {
      return const EdgeInsets.symmetric(horizontal: 32.0); // 桌面端
    }
  }

  /// 响应式垂直边距助手
  static EdgeInsetsGeometry getResponsiveVerticalPadding(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return const EdgeInsets.symmetric(vertical: 8.0); // 移动端
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return const EdgeInsets.symmetric(vertical: 12.0); // 平板端
    } else {
      return const EdgeInsets.symmetric(vertical: 16.0); // 桌面端
    }
  }

  /// 获取响应式最大宽度
  static double getResponsiveMaxWidth(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return screenWidth; // 移动端全宽
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return AppBreakpoints.mediumLarge; // 平板端限制宽度
    } else {
      return AppBreakpoints.large; // 桌面端限制宽度
    }
  }

  // ============================================================
  // THEME ACCESSORS / 主题访问器
  // ============================================================

  /// Light theme / 亮色主题
  ///
  /// Returns the Mindriver light theme with Material 3 design
  /// 返回 Mindriver 亮色主题，使用 Material 3 设计
  static ThemeData get lightTheme => MindriverTheme.lightTheme;

  /// Dark theme / 暗色主题
  ///
  /// Returns the Mindriver dark theme with Material 3 design
  /// 返回 Mindriver 暗色主题，使用 Material 3 设计
  static ThemeData get darkTheme => MindriverTheme.darkTheme;
}
