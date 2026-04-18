import 'package:flutter/widgets.dart';

import 'package:personal_ai_assistant/core/constants/breakpoints.dart';

/// Spacing system for the Personal AI Assistant.
///
/// Follows a 4-point grid scale for consistent, predictable spacing.
class AppSpacing {
  AppSpacing._();

  static const double xs = 4; // tight: icon-text gap, compact elements
  static const double xxs = 2; // minimal: fine-grained spacing
  static const double sm = 8; // small: within-group spacing
  static const double smMd = 12; // medium-small: list item internal
  static const double md = 16; // standard: default element gap (most used)
  static const double mdLg = 20; // medium-large: card content padding
  static const double lg = 24; // large: section separators
  static const double xl = 32; // extra-large: major block separators
  static const double xxl = 48; // page-level whitespace
}

/// Responsive spacing data with compact (mobile) and standard (tablet/desktop) variants.
class AppSpacingData {
  const AppSpacingData({
    required this.xxs,
    required this.xs,
    required this.sm,
    required this.smMd,
    required this.md,
    required this.mdLg,
    required this.lg,
    required this.xl,
    required this.xxl,
  });

  final double xxs;
  final double xs;
  final double sm;
  final double smMd;
  final double md;
  final double mdLg;
  final double lg;
  final double xl;
  final double xxl;

  static const standard = AppSpacingData(
    xxs: 2,
    xs: 4,
    sm: 8,
    smMd: 12,
    md: 16,
    mdLg: 20,
    lg: 24,
    xl: 32,
    xxl: 48,
  );

  static const compact = AppSpacingData(
    xxs: 1,
    xs: 3,
    sm: 6,
    smMd: 8,
    md: 12,
    mdLg: 14,
    lg: 16,
    xl: 20,
    xxl: 28,
  );
}

/// Provides responsive spacing via [BuildContext].
///
/// Returns [AppSpacingData.compact] on mobile (<600px),
/// [AppSpacingData.standard] otherwise.
extension SpacingExtension on BuildContext {
  AppSpacingData get spacing =>
      MediaQuery.sizeOf(this).width < Breakpoints.medium
          ? AppSpacingData.compact
          : AppSpacingData.standard;
}
