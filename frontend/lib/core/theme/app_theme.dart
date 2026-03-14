import 'package:flutter/material.dart';
import '../constants/app_spacing.dart';
import '../constants/breakpoints.dart';
import 'mindriver_theme.dart';

/// AppTheme - Main theme accessor
/// AppTheme - 主主题访问器
///
/// This class wraps the MindriverTheme for backward compatibility
/// 此类包装 MindriverTheme 以保持向后兼容性
class AppTheme {
  AppTheme._();

  // ============================================================
  // RESPONSIVE HELPERS / 响应式助手
  // ============================================================

  /// 响应式边距助手
  static EdgeInsetsGeometry getResponsivePadding(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return const EdgeInsets.all(AppSpacing.lg); // 移动端
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return const EdgeInsets.all(AppSpacing.xl); // 平板端
    } else {
      return const EdgeInsets.all(AppSpacing.xxl); // 桌面端
    }
  }

  /// 响应式水平边距助手
  static EdgeInsetsGeometry getResponsiveHorizontalPadding(
    BuildContext context,
  ) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return const EdgeInsets.symmetric(horizontal: AppSpacing.lg); // 移动端
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return const EdgeInsets.symmetric(horizontal: AppSpacing.xl); // 平板端
    } else {
      return const EdgeInsets.symmetric(horizontal: AppSpacing.xxl); // 桌面端
    }
  }

  /// 响应式垂直边距助手
  static EdgeInsetsGeometry getResponsiveVerticalPadding(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;

    if (screenWidth < AppBreakpoints.medium) {
      return const EdgeInsets.symmetric(vertical: AppSpacing.sm); // 移动端
    } else if (screenWidth < AppBreakpoints.mediumLarge) {
      return const EdgeInsets.symmetric(vertical: AppSpacing.md); // 平板端
    } else {
      return const EdgeInsets.symmetric(vertical: AppSpacing.lg); // 桌面端
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
