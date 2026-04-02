import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import 'package:personal_ai_assistant/core/theme/font_combination.dart';

/// Safely resolve a Google Font, falling back to a plain TextStyle on failure.
TextStyle tryGetFont(String fontFamily, TextStyle textStyle) {
  try {
    return GoogleFonts.getFont(fontFamily, textStyle: textStyle);
  } on Object {
    return textStyle.copyWith(fontFamily: fontFamily);
  }
}

/// A preview card that renders a typography specimen for a font combination.
///
/// Shows heading, body, secondary, caption, and CJK text samples using
/// the given [combo]'s heading and body fonts.
class FontComboCard extends StatelessWidget {
  const FontComboCard({required this.combo, super.key});

  final FontCombination combo;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;

    return Card(
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: scheme.outlineVariant),
      ),
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Display heading
            Text(
              'Stella',
              style: tryGetFont(
                combo.headingFontFamily,
                TextStyle(
                  fontSize: 44,
                  fontWeight: FontWeight.w600,
                  height: 1.05,
                  letterSpacing: -1.5,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 10),

            // Headline
            Text(
              'Your AI Assistant',
              style: tryGetFont(
                combo.headingFontFamily,
                TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w600,
                  height: 1.15,
                  letterSpacing: -0.5,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 10),

            // Body text
            Text(
              'Body text for reading content with comfortable line height. '
              'This demonstrates how the font performs in paragraphs.',
              style: tryGetFont(
                combo.bodyFontFamily,
                TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w400,
                  height: 1.65,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 8),

            // Secondary text
            Text(
              'Secondary text at 14px for descriptions and metadata.',
              style: tryGetFont(
                combo.bodyFontFamily,
                TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w400,
                  height: 1.6,
                  color: scheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 8),

            // Caption
            Text(
              'Caption text at 13px for timestamps',
              style: tryGetFont(
                combo.bodyFontFamily,
                TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w400,
                  height: 1.4,
                  color: scheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 10),

            // CJK text
            Text(
              '你好世界 · 个人智能助手 · 播客转录',
              style: tryGetFont(
                combo.bodyFontFamily,
                TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w400,
                  height: 1.6,
                  color: scheme.onSurface,
                  fontFamilyFallback: const [
                    'Noto Sans SC',
                    'PingFang SC',
                    'Microsoft YaHei',
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
