import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'app_colors.dart';

/// Mindriver Theme Configuration / Mindriver 主题配置
///
/// Complete Material 3 theme system with Light and Dark variants
/// 完整的 Material 3 主题系统，包含亮色和暗色变体
class MindriverTheme {
  MindriverTheme._();

  // ============================================================
  // LIGHT THEME / 亮色主题
  // ============================================================

  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.light,

      // Color Scheme - Manual mapping for precise control
      colorScheme: ColorScheme.light(
        // Primary - #0070D0 with white text for good contrast
        primary: AppColors.primary,
        onPrimary: Colors.white,
        primaryContainer: AppColors.primary.withValues(alpha: 0.1),
        onPrimaryContainer: AppColors.primary,

        // Secondary - Indigo
        secondary: AppColors.indigo,
        onSecondary: Colors.white,
        secondaryContainer: AppColors.indigo.withValues(alpha: 0.1),
        onSecondaryContainer: AppColors.indigo,

        // Tertiary - Leaf green (deep enough for white text)
        tertiary: const Color(0xFF5A9E32), // Slightly darker leaf for contrast
        onTertiary: Colors.white,
        tertiaryContainer: AppColors.leaf.withValues(alpha: 0.15),
        onTertiaryContainer: const Color(0xFF4A8528),

        // Surface colors
        surface: AppColors.lightSurface,
        onSurface: AppColors.lightTextPrimary,
        surfaceContainerHighest: AppColors.lightSurfaceVariant,
        onSurfaceVariant: AppColors.lightTextSecondary,

        // Error
        error: AppColors.error,
        onError: Colors.white,
        errorContainer: AppColors.error.withValues(alpha: 0.1),
        onErrorContainer: AppColors.error,

        // Outline
        outline: AppColors.lightOutline,
        outlineVariant: AppColors.lightOutline.withValues(alpha: 0.5),
      ),

      // Scaffold background color / 脚手架背景色
      scaffoldBackgroundColor: AppColors.lightBackground,

      // AppBar Theme / 应用栏主题
      appBarTheme: AppBarTheme(
        backgroundColor: AppColors.lightSurface,
        foregroundColor: AppColors.lightTextPrimary,
        elevation: 0,
        scrolledUnderElevation: 1,
        shadowColor: Colors.black.withValues(alpha: 0.05),
        centerTitle: true,
        systemOverlayStyle: const SystemUiOverlayStyle(
          statusBarColor: Colors.transparent,
          statusBarIconBrightness: Brightness.dark,
          statusBarBrightness: Brightness.light,
        ),
        titleTextStyle: const TextStyle(
          color: AppColors.lightTextPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w600,
          letterSpacing: -0.5,
        ),
      ),

      // Card Theme / 卡片主题
      cardTheme: CardThemeData(
        color: AppColors.lightSurface,
        elevation: 0,
        shadowColor: Colors.black.withValues(alpha: 0.05),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: AppColors.lightOutline, width: 1),
        ),
        margin: const EdgeInsets.all(8),
      ),

      // ListTile Theme / 列表项主题
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        tileColor: Colors.transparent,
        selectedTileColor: AppColors.primary.withValues(alpha: 0.08),
        iconColor: AppColors.lightTextSecondary,
        selectedColor: AppColors.primary,
        textColor: AppColors.lightTextPrimary,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
      ),

      // Elevated Button Theme / 凸起按钮主题
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: AppColors.primary,
          foregroundColor: Colors.white,
          elevation: 0,
          shadowColor: Colors.transparent,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          textStyle: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Text Button Theme / 文本按钮主题
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: AppColors.primary,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          textStyle: const TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Outlined Button Theme / 轮廓按钮主题
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.primary,
          side: const BorderSide(color: AppColors.primary, width: 1.5),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          textStyle: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Input Decoration Theme / 输入框主题
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.lightSurfaceVariant.withValues(alpha: 0.5),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.lightOutline),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.lightOutline),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.primary, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.error),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: AppColors.error, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        hintStyle: TextStyle(
          color: AppColors.lightTextTertiary,
          fontSize: 14,
        ),
        labelStyle: const TextStyle(
          color: AppColors.lightTextSecondary,
          fontSize: 12,
        ),
      ),

      // Chip Theme / 标签主题
      chipTheme: ChipThemeData(
        backgroundColor: AppColors.lightSurfaceVariant,
        selectedColor: AppColors.primary.withValues(alpha: 0.12),
        disabledColor: AppColors.lightSurfaceVariant.withValues(alpha: 0.5),
        labelStyle: const TextStyle(
          color: AppColors.lightTextPrimary,
          fontSize: 12,
        ),
        secondaryLabelStyle: const TextStyle(
          color: AppColors.primary,
          fontSize: 12,
          fontWeight: FontWeight.w600,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: const BorderSide(color: AppColors.lightOutline),
        ),
        side: const BorderSide(color: AppColors.lightOutline),
      ),

      // Divider Theme / 分割线主题
      dividerTheme: const DividerThemeData(
        color: AppColors.lightOutline,
        thickness: 1,
        space: 1,
      ),

      // Bottom Navigation Bar Theme / 底部导航栏主题
      bottomNavigationBarTheme: BottomNavigationBarThemeData(
        backgroundColor: AppColors.lightSurface,
        selectedItemColor: AppColors.primary,
        unselectedItemColor: AppColors.lightTextTertiary,
        type: BottomNavigationBarType.fixed,
        elevation: 8,
        selectedLabelStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
        ),
        unselectedLabelStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w400,
        ),
      ),

      // Snack Bar Theme / 提示条主题
      snackBarTheme: SnackBarThemeData(
        backgroundColor: AppColors.darkSurface,
        contentTextStyle: const TextStyle(
          color: AppColors.darkTextPrimary,
          fontSize: 12,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
        behavior: SnackBarBehavior.floating,
        elevation: 8,
      ),

      // Floating Action Button Theme / 悬浮按钮主题
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: AppColors.primary,
        foregroundColor: Colors.white,
        elevation: 4,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
      ),

      // Text Theme / 文字主题
      textTheme: _buildTextTheme(AppColors.lightTextPrimary, AppColors.lightTextSecondary, AppColors.lightTextTertiary),

      // Icon Theme / 图标主题
      iconTheme: const IconThemeData(
        color: AppColors.lightTextSecondary,
        size: 24,
      ),

      // Extensions / 扩展
      extensions: const <ThemeExtension<dynamic>>[
        MindriverThemeExtension.light,
      ],
    );
  }

  // ============================================================
  // DARK THEME / 暗色主题
  // ============================================================

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,

      // Color Scheme - Manual mapping with proper contrast
      colorScheme: ColorScheme.dark(
        primary: Color(0xFF2D2D2D),
        onPrimary: AppColors.darkTextPrimary,
        primaryContainer: Color(0xFF3A3A3A),
        onPrimaryContainer: AppColors.darkTextPrimary,

        secondary: Color(0xFF4A4A4A),
        onSecondary: AppColors.darkTextPrimary,
        secondaryContainer: Color(0xFF262626),
        onSecondaryContainer: AppColors.darkTextPrimary,

        // Tertiary - Lighter green
        tertiary: const Color(0xFF85D45B),
        onTertiary: AppColors.darkBackground,
        tertiaryContainer: AppColors.leaf.withValues(alpha: 0.2),
        onTertiaryContainer: const Color(0xFF85D45B),

        // Surface colors
        surface: AppColors.darkSurface,
        onSurface: AppColors.darkTextPrimary,
        surfaceContainerHighest: AppColors.darkSurfaceVariant,
        onSurfaceVariant: AppColors.darkTextSecondary,

        // Error
        error: const Color(0xFFFC8181),
        onError: AppColors.darkBackground,
        errorContainer: AppColors.error.withValues(alpha: 0.2),
        onErrorContainer: const Color(0xFFFC8181),

        // Outline
        outline: AppColors.darkOutline,
        outlineVariant: AppColors.darkOutline.withValues(alpha: 0.5),
      ),

      // Scaffold background color / 脚手架背景色
      scaffoldBackgroundColor: AppColors.darkBackground,

      // AppBar Theme / 应用栏主题
      appBarTheme: AppBarTheme(
        backgroundColor: AppColors.darkSurface,
        foregroundColor: AppColors.darkTextPrimary,
        elevation: 0,
        scrolledUnderElevation: 1,
        shadowColor: Colors.black.withValues(alpha: 0.3),
        centerTitle: true,
        systemOverlayStyle: const SystemUiOverlayStyle(
          statusBarColor: Colors.transparent,
          statusBarIconBrightness: Brightness.light,
          statusBarBrightness: Brightness.dark,
        ),
        titleTextStyle: const TextStyle(
          color: AppColors.darkTextPrimary,
          fontSize: 16,
          fontWeight: FontWeight.w600,
          letterSpacing: -0.5,
        ),
      ),

      // Card Theme / 卡片主题
      cardTheme: CardThemeData(
        color: AppColors.darkSurfaceVariant,
        elevation: 0,
        shadowColor: Colors.black.withValues(alpha: 0.3),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: AppColors.darkOutline.withValues(alpha: 0.3), width: 1),
        ),
        margin: const EdgeInsets.all(8),
      ),

      // ListTile Theme / 列表项主题
      listTileTheme: ListTileThemeData(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        tileColor: Colors.transparent,
        selectedTileColor: Colors.white.withValues(alpha: 0.06),
        iconColor: AppColors.darkTextSecondary,
        selectedColor: AppColors.darkTextPrimary,
        textColor: AppColors.darkTextPrimary,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
      ),

      // Elevated Button Theme / 凸起按钮主题
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: const Color(0xFF2D2D2D),
          foregroundColor: AppColors.darkTextPrimary,
          elevation: 0,
          shadowColor: Colors.transparent,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          textStyle: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Text Button Theme / 文本按钮主题
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(
          foregroundColor: AppColors.darkTextPrimary,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          textStyle: const TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Outlined Button Theme / 轮廓按钮主题
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: AppColors.darkTextPrimary,
          side: BorderSide(color: AppColors.darkOutline, width: 1.5),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          textStyle: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
            letterSpacing: 0.2,
          ),
        ),
      ),

      // Input Decoration Theme / 输入框主题
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: AppColors.darkSurfaceVariant.withValues(alpha: 0.5),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: AppColors.darkOutline.withValues(alpha: 0.5)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: AppColors.darkOutline.withValues(alpha: 0.5)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: AppColors.darkTextPrimary, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: Color(0xFFFC8181)),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: const BorderSide(color: Color(0xFFFC8181), width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        hintStyle: TextStyle(
          color: AppColors.darkTextTertiary,
          fontSize: 14,
        ),
        labelStyle: const TextStyle(
          color: AppColors.darkTextSecondary,
          fontSize: 12,
        ),
      ),

      // Chip Theme / 标签主题
      chipTheme: ChipThemeData(
        backgroundColor: AppColors.darkSurfaceVariant,
        selectedColor: Colors.white.withValues(alpha: 0.08),
        disabledColor: AppColors.darkSurfaceVariant.withValues(alpha: 0.3),
        labelStyle: const TextStyle(
          color: AppColors.darkTextPrimary,
          fontSize: 12,
        ),
        secondaryLabelStyle: const TextStyle(
          color: AppColors.darkTextPrimary,
          fontSize: 12,
          fontWeight: FontWeight.w600,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
          side: BorderSide(color: AppColors.darkOutline.withValues(alpha: 0.3)),
        ),
        side: BorderSide(color: AppColors.darkOutline.withValues(alpha: 0.3)),
      ),

      // Divider Theme / 分割线主题
      dividerTheme: DividerThemeData(
        color: AppColors.darkOutline.withValues(alpha: 0.3),
        thickness: 1,
        space: 1,
      ),

      // Bottom Navigation Bar Theme / 底部导航栏主题
      bottomNavigationBarTheme: BottomNavigationBarThemeData(
        backgroundColor: AppColors.darkSurface,
        selectedItemColor: AppColors.darkTextPrimary,
        unselectedItemColor: AppColors.darkTextTertiary,
        type: BottomNavigationBarType.fixed,
        elevation: 8,
        selectedLabelStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
        ),
        unselectedLabelStyle: const TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w400,
        ),
      ),

      // Snack Bar Theme / 提示条主题
      snackBarTheme: SnackBarThemeData(
        backgroundColor: AppColors.darkSurfaceVariant,
        contentTextStyle: const TextStyle(
          color: AppColors.darkTextPrimary,
          fontSize: 12,
        ),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(8),
        ),
        behavior: SnackBarBehavior.floating,
        elevation: 8,
      ),

      // Floating Action Button Theme / 悬浮按钮主题
      floatingActionButtonTheme: FloatingActionButtonThemeData(
        backgroundColor: const Color(0xFF2D2D2D),
        foregroundColor: AppColors.darkTextPrimary,
        elevation: 4,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
        ),
      ),

      // Text Theme / 文字主题
      textTheme: _buildTextTheme(AppColors.darkTextPrimary, AppColors.darkTextSecondary, AppColors.darkTextTertiary),

      // Icon Theme / 图标主题
      iconTheme: const IconThemeData(
        color: AppColors.darkTextSecondary,
        size: 24,
      ),

      // Extensions / 扩展
      extensions: const <ThemeExtension<dynamic>>[
        MindriverThemeExtension.dark,
      ],
    );
  }

  // ============================================================
  // TEXT THEME BUILDER / 文字主题构建器
  // ============================================================

  static TextTheme _buildTextTheme(Color primary, Color secondary, Color tertiary) {
    return TextTheme(
      // Display styles - Largest text on screen
      displayLarge: TextStyle(
        color: primary,
        fontSize: 54,
        fontWeight: FontWeight.w400,
        letterSpacing: -0.25,
      ),
      displayMedium: TextStyle(
        color: primary,
        fontSize: 42,
        fontWeight: FontWeight.w400,
        letterSpacing: 0,
      ),
      displaySmall: TextStyle(
        color: primary,
        fontSize: 34,
        fontWeight: FontWeight.w400,
        letterSpacing: 0,
      ),

      // Headline styles - High-emphasis text
      headlineLarge: TextStyle(
        color: primary,
        fontSize: 29,
        fontWeight: FontWeight.w600,
        letterSpacing: -0.5,
      ),
      headlineMedium: TextStyle(
        color: primary,
        fontSize: 26,
        fontWeight: FontWeight.w600,
        letterSpacing: -0.25,
      ),
      headlineSmall: TextStyle(
        color: primary,
        fontSize: 22,
        fontWeight: FontWeight.w600,
        letterSpacing: 0,
      ),

      // Title styles - Medium-emphasis text
      titleLarge: TextStyle(
        color: primary,
        fontSize: 19,
        fontWeight: FontWeight.w500,
        letterSpacing: 0,
      ),
      titleMedium: TextStyle(
        color: primary,
        fontSize: 14,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.15,
      ),
      titleSmall: TextStyle(
        color: primary,
        fontSize: 12,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.1,
      ),

      // Body styles - Body text and subtitles
      bodyLarge: TextStyle(
        color: primary,
        fontSize: 14,
        fontWeight: FontWeight.w400,
        letterSpacing: 0.5,
      ),
      bodyMedium: TextStyle(
        color: primary,
        fontSize: 12,
        fontWeight: FontWeight.w400,
        letterSpacing: 0.25,
      ),
      bodySmall: TextStyle(
        color: secondary,
        fontSize: 10,
        fontWeight: FontWeight.w400,
        letterSpacing: 0.4,
      ),

      // Label styles - Smaller text like captions
      labelLarge: TextStyle(
        color: primary,
        fontSize: 12,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.1,
      ),
      labelMedium: TextStyle(
        color: secondary,
        fontSize: 10,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.5,
      ),
      labelSmall: TextStyle(
        color: tertiary,
        fontSize: 9,
        fontWeight: FontWeight.w500,
        letterSpacing: 0.5,
      ),
    );
  }
}
