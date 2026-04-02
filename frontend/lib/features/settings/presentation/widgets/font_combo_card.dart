import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import 'package:personal_ai_assistant/core/theme/font_combination.dart';

/// Safely resolve a Google Font, falling back to a plain TextStyle on failure.
TextStyle _tryGetFont(String fontFamily, TextStyle textStyle) {
  try {
    return GoogleFonts.getFont(fontFamily, textStyle: textStyle);
  } catch (_) {
    return textStyle.copyWith(fontFamily: fontFamily);
  }
}

/// A card that previews a font combination with a compact typography specimen.
///
/// Shows a checkmark indicator when selected and calls [onTap] for selection.
class FontComboCard extends StatelessWidget {
  const FontComboCard({
    super.key,
    required this.combo,
    required this.isSelected,
    this.onTap,
  });

  final FontCombination combo;
  final bool isSelected;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;

    return Card(
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: isSelected
            ? BorderSide(color: scheme.primary, width: 2)
            : BorderSide(color: scheme.outlineVariant),
      ),
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header row: label + selection indicator
              Row(
                children: [
                  Expanded(
                    child: Text(
                      combo.displayName,
                      style: _tryGetFont(
                        combo.bodyFontFamily,
                        TextStyle(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          letterSpacing: 0.3,
                          color: scheme.primary,
                        ),
                      ),
                    ),
                  ),
                  if (isSelected)
                    Icon(Icons.check_circle, color: scheme.primary, size: 20),
                ],
              ),
              const SizedBox(height: 16),

              // Display heading
              Text(
                'Stella',
                style: _tryGetFont(
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
                style: _tryGetFont(
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
                style: _tryGetFont(
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
                style: _tryGetFont(
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
                style: _tryGetFont(
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
                style: _tryGetFont(
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
      ),
    );
  }
}
