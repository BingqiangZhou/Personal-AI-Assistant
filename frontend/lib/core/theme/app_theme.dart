import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';

import 'app_colors.dart';
import 'responsive_helpers.dart';

/// ============================================================
/// Refined Minimal Design System - 简约现代设计系统
///
/// Typography System:
/// - Headings: Outfit (几何感、精致、现代)
/// - Body: Plus Jakarta Sans (优雅、清晰、易读)
/// ============================================================

class AppTheme {
  AppTheme._();

  // ============================================================
  // RESPONSIVE HELPERS (re-exported from ResponsiveHelpers)
  // 响应式助手（从 ResponsiveHelpers 重新导出）
  // ============================================================

  /// 响应式边距助手
  static EdgeInsetsGeometry getResponsivePadding(BuildContext context) =>
      ResponsiveHelpers.getResponsivePadding(context);

  /// 响应式水平边距助手
  static EdgeInsetsGeometry getResponsiveHorizontalPadding(BuildContext context) =>
      ResponsiveHelpers.getResponsiveHorizontalPadding(context);

  /// 响应式垂直边距助手
  static EdgeInsetsGeometry getResponsiveVerticalPadding(BuildContext context) =>
      ResponsiveHelpers.getResponsiveVerticalPadding(context);

  /// 获取响应式最大宽度
  static double getResponsiveMaxWidth(BuildContext context) =>
      ResponsiveHelpers.getResponsiveMaxWidth(context);

  // ============================================================
  // THEME ACCESSORS / 主题访问器
  // ============================================================

  static ThemeData get lightTheme => _buildTheme(Brightness.light);

  static ThemeData get darkTheme => _buildTheme(Brightness.dark);

  static ThemeData _buildTheme(Brightness brightness) {
    final isDark = brightness == Brightness.dark;
    final scheme = _buildColorScheme(brightness);
    final textTheme = _buildTextTheme(
      scheme.onSurface,
      scheme.onSurfaceVariant,
      isDark ? AppColors.darkTextTertiary : AppColors.lightTextTertiary,
    );
    final extension = isDark
        ? AppThemeExtension.dark
        : AppThemeExtension.light;

    final googleTextTheme = _buildGoogleTextTheme(textTheme);

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme,
      scaffoldBackgroundColor: isDark
          ? AppColors.darkBackground
          : AppColors.lightBackground,
      textTheme: googleTextTheme,
      fontFamily: GoogleFonts.plusJakartaSans().fontFamily,
      appBarTheme: AppBarTheme(
        backgroundColor: Colors.transparent,
        foregroundColor: scheme.onSurface,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        scrolledUnderElevation: 0,
        centerTitle: false,
        systemOverlayStyle: SystemUiOverlayStyle(
          statusBarColor: Colors.transparent,
          statusBarBrightness: isDark ? Brightness.dark : Brightness.light,
          statusBarIconBrightness: isDark ? Brightness.light : Brightness.dark,
          systemNavigationBarColor: Colors.transparent,
          systemNavigationBarDividerColor: Colors.transparent,
          systemNavigationBarIconBrightness: isDark
              ? Brightness.light
              : Brightness.dark,
        ),
        titleTextStyle: GoogleFonts.outfit(
          textStyle: textTheme.titleLarge?.copyWith(
            color: scheme.onSurface,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      cardTheme: CardThemeData(
        color: scheme.surface,
        elevation: 0,
        shadowColor: extension.shadowMd.color,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(extension.cardRadius),
          side: BorderSide(color: scheme.outlineVariant),
        ),
      ),
      dialogTheme: DialogThemeData(
        backgroundColor: scheme.surface,
        surfaceTintColor: Colors.transparent,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(extension.panelRadius),
          side: BorderSide(color: scheme.outlineVariant),
        ),
        titleTextStyle: GoogleFonts.outfit(
          textStyle: textTheme.headlineSmall,
        ),
      ),
      dividerTheme: DividerThemeData(
        color: scheme.outlineVariant.withValues(alpha: 0.5),
        thickness: 1,
        space: 1,
      ),
      iconTheme: IconThemeData(color: scheme.onSurfaceVariant, size: 22),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: isDark
            ? scheme.surfaceContainerHighest
            : scheme.surface,
        hintStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.bodyMedium?.copyWith(
            color: scheme.onSurfaceVariant.withValues(alpha: 0.7),
          ),
        ),
        labelStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.labelMedium?.copyWith(
            color: scheme.onSurfaceVariant,
          ),
        ),
        contentPadding: const EdgeInsets.symmetric(
          horizontal: 16,
          vertical: 14,
        ),
        border: _inputBorder(extension, scheme.outlineVariant),
        enabledBorder: _inputBorder(extension, scheme.outlineVariant),
        focusedBorder: _inputBorder(
          extension,
          scheme.primary.withValues(alpha: 0.6),
          width: 1.4,
        ),
        errorBorder: _inputBorder(extension, scheme.error),
        focusedErrorBorder: _inputBorder(extension, scheme.error, width: 1.4),
      ),
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        iconColor: scheme.onSurfaceVariant,
        textColor: scheme.onSurface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(extension.cardRadius)),
      ),
      chipTheme: ChipThemeData(
        backgroundColor: scheme.surfaceContainerHighest,
        selectedColor: scheme.primary.withValues(alpha: 0.14),
        disabledColor: scheme.surfaceContainerHighest,
        secondarySelectedColor: scheme.primary.withValues(alpha: 0.16),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.5)),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        labelStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.labelMedium?.copyWith(color: scheme.onSurface),
        ),
        secondaryLabelStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.labelMedium?.copyWith(
            color: scheme.primary,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      snackBarTheme: SnackBarThemeData(
        backgroundColor: scheme.surface,
        contentTextStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.bodyMedium?.copyWith(
            color: scheme.onSurface,
          ),
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(extension.cardRadius),
          side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.35)),
        ),
        behavior: SnackBarBehavior.floating,
        elevation: 0,
      ),
      progressIndicatorTheme: ProgressIndicatorThemeData(
        color: scheme.primary,
        circularTrackColor: scheme.surfaceContainerHighest,
        linearTrackColor: scheme.surfaceContainerHighest,
      ),
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: scheme.primary,
        foregroundColor: scheme.onPrimary,
        elevation: 0,
        focusElevation: 0,
        hoverElevation: 0,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(extension.buttonRadius)),
      ),
      navigationBarTheme: NavigationBarThemeData(
        backgroundColor: Colors.transparent,
        surfaceTintColor: Colors.transparent,
        elevation: 0,
        height: 72,
        labelTextStyle: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return GoogleFonts.plusJakartaSans(
            textStyle: textTheme.labelSmall?.copyWith(
              fontWeight: selected ? FontWeight.w600 : FontWeight.w500,
              color: selected ? scheme.onSurface : scheme.onSurfaceVariant,
            ),
          );
        }),
        iconTheme: WidgetStateProperty.resolveWith((states) {
          final selected = states.contains(WidgetState.selected);
          return IconThemeData(
            size: 22,
            color: selected
                ? scheme.onPrimaryContainer
                : scheme.onSurfaceVariant,
          );
        }),
        indicatorColor: scheme.primary.withValues(alpha: isDark ? 0.22 : 0.14),
      ),
      navigationRailTheme: NavigationRailThemeData(
        backgroundColor: Colors.transparent,
        indicatorColor: scheme.primary.withValues(alpha: isDark ? 0.18 : 0.12),
        selectedIconTheme: IconThemeData(color: scheme.onPrimaryContainer),
        unselectedIconTheme: IconThemeData(color: scheme.onSurfaceVariant),
        selectedLabelTextStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.labelMedium?.copyWith(
            color: scheme.onSurface,
            fontWeight: FontWeight.w600,
          ),
        ),
        unselectedLabelTextStyle: GoogleFonts.plusJakartaSans(
          textStyle: textTheme.labelMedium?.copyWith(
            color: scheme.onSurfaceVariant,
          ),
        ),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: _buttonStyle(
          scheme.primary,
          scheme.onPrimary,
          radius: extension.buttonRadius,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 16),
          textStyle: GoogleFonts.plusJakartaSans(
            textStyle: textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ),
      filledButtonTheme: FilledButtonThemeData(
        style: _buttonStyle(
          scheme.primary,
          scheme.onPrimary,
          radius: extension.buttonRadius,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 16),
          textStyle: GoogleFonts.plusJakartaSans(
            textStyle: textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: scheme.onSurface,
          side: BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.6)),
          backgroundColor: Colors.transparent,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(extension.buttonRadius),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 15),
          textStyle: GoogleFonts.plusJakartaSans(
            textStyle: textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: scheme.onSurface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(extension.buttonRadius),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          textStyle: GoogleFonts.plusJakartaSans(
            textStyle: textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w600,
            ),
          ),
        ),
      ),
      checkboxTheme: CheckboxThemeData(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(4)),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      segmentedButtonTheme: SegmentedButtonThemeData(
        style: ButtonStyle(
          backgroundColor: WidgetStateProperty.resolveWith((states) {
            if (states.contains(WidgetState.selected)) {
              return scheme.primary.withValues(alpha: isDark ? 0.18 : 0.12);
            }
            return scheme.surfaceContainerHighest;
          }),
          foregroundColor: WidgetStateProperty.resolveWith((states) {
            return states.contains(WidgetState.selected)
                ? scheme.onSurface
                : scheme.onSurfaceVariant;
          }),
          side: WidgetStatePropertyAll(
            BorderSide(color: scheme.outlineVariant.withValues(alpha: 0.6)),
          ),
          shape: WidgetStatePropertyAll(
            RoundedRectangleBorder(borderRadius: BorderRadius.circular(extension.buttonRadius)),
          ),
        ),
      ),
      extensions: <ThemeExtension<dynamic>>[extension],
    );
  }

  static ColorScheme _buildColorScheme(Brightness brightness) {
    final isDark = brightness == Brightness.dark;
    final base = ColorScheme.fromSeed(
      seedColor: AppColors.primary,
      brightness: brightness,
    );

    return base.copyWith(
      primary: isDark ? const Color(0xFF60A5FA) : AppColors.primary,
      onPrimary: isDark ? const Color(0xFF0A0A0A) : Colors.white,
      primaryContainer: isDark
          ? AppColors.primaryContainerDark
          : AppColors.primaryContainer,
      onPrimaryContainer: isDark
          ? AppColors.darkTextPrimary
          : const Color(0xFF1E3A8A),
      secondary: isDark ? const Color(0xFF94A3B8) : const Color(0xFF64748B),
      onSecondary: isDark ? const Color(0xFF0A0A0A) : Colors.white,
      secondaryContainer: isDark
          ? const Color(0xFF1E293B)
          : const Color(0xFFF1F5F9),
      onSecondaryContainer: isDark
          ? AppColors.darkTextPrimary
          : const Color(0xFF334155),
      tertiary: isDark ? const Color(0xFF22C55E) : const Color(0xFF16A34A),
      onTertiary: isDark ? const Color(0xFF0A0A0A) : Colors.white,
      tertiaryContainer: isDark
          ? const Color(0xFF14532D)
          : const Color(0xFFDCFCE7),
      onTertiaryContainer: isDark
          ? const Color(0xFFECFDF5)
          : const Color(0xFF166534),
      error: AppColors.error,
      onError: Colors.white,
      errorContainer: isDark
          ? const Color(0xFF451A1B)
          : const Color(0xFFFEE2E2),
      onErrorContainer: isDark
          ? const Color(0xFFFECACA)
          : const Color(0xFF7F1D1D),
      surface: isDark ? AppColors.darkSurface : AppColors.lightSurface,
      onSurface: isDark
          ? AppColors.darkTextPrimary
          : AppColors.lightTextPrimary,
      onSurfaceVariant: isDark
          ? AppColors.darkTextSecondary
          : AppColors.lightTextSecondary,
      outline: isDark ? AppColors.darkOutline : AppColors.lightOutline,
      outlineVariant: isDark
          ? AppColors.darkOutlineVariant
          : AppColors.lightOutlineVariant,
      shadow: Colors.black,
      scrim: Colors.black,
    );
  }

  static OutlineInputBorder _inputBorder(
    AppThemeExtension extension,
    Color color, {
    double width = 1,
  }) {
    return OutlineInputBorder(
      borderRadius: BorderRadius.circular(extension.inputRadius),
      borderSide: BorderSide(color: color, width: width),
    );
  }

  static ButtonStyle _buttonStyle(
    Color backgroundColor,
    Color foregroundColor, {
    required double radius,
    required double elevation,
    required EdgeInsetsGeometry padding,
    required TextStyle? textStyle,
  }) {
    return ElevatedButton.styleFrom(
      backgroundColor: backgroundColor,
      foregroundColor: foregroundColor,
      elevation: elevation,
      shadowColor: Colors.transparent,
      surfaceTintColor: Colors.transparent,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(radius),
      ),
      padding: padding,
      textStyle: textStyle,
    );
  }

  /// Build the base text theme with proper hierarchy
  static TextTheme _buildTextTheme(
    Color primary,
    Color secondary,
    Color tertiary,
  ) {
    const base = TextTheme();
    return base.copyWith(
      displaySmall: TextStyle(
        fontSize: 48,
        height: 1.1,
        fontWeight: FontWeight.w500,
        letterSpacing: -1.5,
        color: primary,
      ),
      headlineLarge: TextStyle(
        fontSize: 32,
        height: 1.15,
        fontWeight: FontWeight.w600,
        letterSpacing: -1.0,
        color: primary,
      ),
      headlineMedium: TextStyle(
        fontSize: 24,
        height: 1.2,
        fontWeight: FontWeight.w600,
        letterSpacing: -0.5,
        color: primary,
      ),
      headlineSmall: TextStyle(
        fontSize: 20,
        height: 1.25,
        fontWeight: FontWeight.w500,
        letterSpacing: -0.3,
        color: primary,
      ),
      titleLarge: TextStyle(
        fontSize: 18,
        height: 1.28,
        fontWeight: FontWeight.w600,
        letterSpacing: -0.2,
        color: primary,
      ),
      titleMedium: TextStyle(
        fontSize: 16,
        height: 1.3,
        fontWeight: FontWeight.w500,
        color: primary,
      ),
      titleSmall: TextStyle(
        fontSize: 14,
        height: 1.32,
        fontWeight: FontWeight.w500,
        color: primary,
      ),
      bodyLarge: TextStyle(
        fontSize: 16,
        height: 1.6,
        fontWeight: FontWeight.w400,
        color: primary,
      ),
      bodyMedium: TextStyle(
        fontSize: 14,
        height: 1.55,
        fontWeight: FontWeight.w400,
        color: secondary,
      ),
      bodySmall: TextStyle(
        fontSize: 12,
        height: 1.45,
        fontWeight: FontWeight.w400,
        color: tertiary,
      ),
      labelLarge: TextStyle(
        fontSize: 14,
        height: 1.2,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.1,
        color: primary,
      ),
      labelMedium: TextStyle(
        fontSize: 12,
        height: 1.15,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.1,
        color: secondary,
      ),
      labelSmall: TextStyle(
        fontSize: 11,
        height: 1.1,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.15,
        color: tertiary,
      ),
    );
  }

  /// Build typography with Outfit + Plus Jakarta Sans
  static TextTheme _buildGoogleTextTheme(TextTheme baseTheme) {
    return baseTheme.copyWith(
      // Display & Headings - Outfit
      displaySmall: GoogleFonts.outfit(
        textStyle: baseTheme.displaySmall,
      ),
      headlineLarge: GoogleFonts.outfit(
        textStyle: baseTheme.headlineLarge,
      ),
      headlineMedium: GoogleFonts.outfit(
        textStyle: baseTheme.headlineMedium,
      ),
      headlineSmall: GoogleFonts.outfit(
        textStyle: baseTheme.headlineSmall,
      ),
      titleLarge: GoogleFonts.outfit(
        textStyle: baseTheme.titleLarge,
      ),
      // Body & Labels - Plus Jakarta Sans
      titleMedium: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.titleMedium,
      ),
      titleSmall: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.titleSmall,
      ),
      bodyLarge: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.bodyLarge,
      ),
      bodyMedium: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.bodyMedium,
      ),
      bodySmall: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.bodySmall,
      ),
      labelLarge: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.labelLarge,
      ),
      labelMedium: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.labelMedium,
      ),
      labelSmall: GoogleFonts.plusJakartaSans(
        textStyle: baseTheme.labelSmall,
      ),
    );
  }
}

// Legacy compatibility
@Deprecated('Use AppTheme instead')
typedef ArcticTheme = AppTheme;
