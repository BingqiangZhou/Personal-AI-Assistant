import 'package:flutter/material.dart';

import 'package:personal_ai_assistant/core/constants/app_spacing.dart';
import 'package:personal_ai_assistant/core/constants/breakpoints.dart';

/// ResponsiveHelpers - Utility methods for responsive layouts
class ResponsiveHelpers {
  ResponsiveHelpers._();

  /// Responsive padding helper
  static EdgeInsetsGeometry getResponsivePadding(BuildContext context) {
    final screenWidth = MediaQuery.sizeOf(context).width;

    if (screenWidth < Breakpoints.medium) {
      return EdgeInsets.all(AppSpacingData.compact.md); // mobile
    } else if (screenWidth < Breakpoints.mediumLarge) {
      return EdgeInsets.all(AppSpacingData.standard.lg); // tablet
    } else {
      return EdgeInsets.all(AppSpacingData.standard.xl); // desktop
    }
  }

  /// Responsive horizontal padding helper
  static EdgeInsetsGeometry getResponsiveHorizontalPadding(
    BuildContext context,
  ) {
    final screenWidth = MediaQuery.sizeOf(context).width;

    if (screenWidth < Breakpoints.medium) {
      return EdgeInsets.symmetric(horizontal: AppSpacingData.compact.md); // mobile
    } else if (screenWidth < Breakpoints.mediumLarge) {
      return EdgeInsets.symmetric(horizontal: AppSpacingData.standard.lg); // tablet
    } else {
      return EdgeInsets.symmetric(horizontal: AppSpacingData.standard.xl); // desktop
    }
  }

  /// Responsive vertical padding helper
  static EdgeInsetsGeometry getResponsiveVerticalPadding(BuildContext context) {
    final screenWidth = MediaQuery.sizeOf(context).width;

    if (screenWidth < Breakpoints.medium) {
      return EdgeInsets.symmetric(vertical: AppSpacingData.compact.sm); // mobile
    } else if (screenWidth < Breakpoints.mediumLarge) {
      return EdgeInsets.symmetric(vertical: AppSpacingData.standard.smMd); // tablet
    } else {
      return EdgeInsets.symmetric(vertical: AppSpacingData.standard.md); // desktop
    }
  }

  /// Get responsive max width
  static double getResponsiveMaxWidth(BuildContext context) {
    final screenWidth = MediaQuery.sizeOf(context).width;

    if (screenWidth < Breakpoints.medium) {
      return screenWidth; // mobile full width
    } else if (screenWidth < Breakpoints.mediumLarge) {
      return Breakpoints.mediumLarge; // tablet limited width
    } else {
      return Breakpoints.large; // desktop limited width
    }
  }
}
