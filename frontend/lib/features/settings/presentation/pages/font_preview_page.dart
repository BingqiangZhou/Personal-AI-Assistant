import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Temporary page to preview and compare font combinations.
/// Remove after selecting the final combination.
class FontPreviewPage extends StatelessWidget {
  const FontPreviewPage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Font Preview')),
      body: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        children: const [
          _FontComboCard(
            label: 'A: Space Grotesk + Inter (Recommended)',
            headingBuilder: GoogleFonts.spaceGrotesk,
            bodyBuilder: GoogleFonts.inter,
          ),
          SizedBox(height: 16),
          _FontComboCard(
            label: 'B: Sora + Inter (Refined Current)',
            headingBuilder: GoogleFonts.sora,
            bodyBuilder: GoogleFonts.inter,
          ),
          SizedBox(height: 16),
          _FontComboCard(
            label: 'C: Plus Jakarta Sans (Superfamily)',
            headingBuilder: GoogleFonts.plusJakartaSans,
            bodyBuilder: GoogleFonts.plusJakartaSans,
          ),
          SizedBox(height: 16),
          _FontComboCard(
            label: 'D: Urbanist + Manrope',
            headingBuilder: GoogleFonts.urbanist,
            bodyBuilder: GoogleFonts.manrope,
          ),
          SizedBox(height: 16),
          _FontComboCard(
            label: 'E: Onest (Variable Superfamily)',
            headingBuilder: GoogleFonts.onest,
            bodyBuilder: GoogleFonts.onest,
          ),
          SizedBox(height: 32),
        ],
      ),
    );
  }
}

class _FontComboCard extends StatelessWidget {
  const _FontComboCard({
    required this.label,
    required this.headingBuilder,
    required this.bodyBuilder,
  });

  final String label;
  final TextStyle Function({TextStyle? textStyle}) headingBuilder;
  final TextStyle Function({TextStyle? textStyle}) bodyBuilder;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;

    return Card(
      margin: EdgeInsets.zero,
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Combo label
            Text(
              label,
              style: bodyBuilder(
                textStyle: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.3,
                  color: scheme.primary,
                ),
              ),
            ),
            const SizedBox(height: 16),

            // Display heading
            Text(
              'Stella',
              style: headingBuilder(
                textStyle: TextStyle(
                  fontSize: 44,
                  fontWeight: FontWeight.w600,
                  height: 1.05,
                  letterSpacing: -1.5,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 12),

            // Headline
            Text(
              'Your AI Assistant',
              style: headingBuilder(
                textStyle: TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.w600,
                  height: 1.15,
                  letterSpacing: -0.5,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 12),

            // Title
            Text(
              'Podcast Episode Title',
              style: headingBuilder(
                textStyle: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w600,
                  height: 1.28,
                  letterSpacing: -0.2,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 10),

            // Body large
            Text(
              'Body text for reading content with comfortable line height. '
              'This demonstrates how the font performs in longer paragraphs '
              'that users will actually read.',
              style: bodyBuilder(
                textStyle: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.w400,
                  height: 1.65,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 8),

            // Body medium (secondary)
            Text(
              'Secondary body text at 14px for descriptions and metadata. '
              'Used throughout the app for episode descriptions and UI labels.',
              style: bodyBuilder(
                textStyle: TextStyle(
                  fontSize: 14,
                  fontWeight: FontWeight.w400,
                  height: 1.6,
                  color: scheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 8),

            // Transcript body (fontSize 15, height 1.6)
            Text(
              'Transcript body text at 15px with 1.6 line height. '
              'This is the size used for podcast transcripts and show notes. '
              'Readability here is critical for the core feature.',
              style: bodyBuilder(
                textStyle: TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.w400,
                  height: 1.6,
                  color: scheme.onSurface,
                ),
              ),
            ),
            const SizedBox(height: 8),

            // Caption (fontSize 13)
            Text(
              'Caption text at 13px for timestamps and subtle metadata.',
              style: bodyBuilder(
                textStyle: TextStyle(
                  fontSize: 13,
                  fontWeight: FontWeight.w400,
                  height: 1.4,
                  color: scheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 8),

            // Labels row
            Row(
              children: [
                Text(
                  'Label Large ',
                  style: bodyBuilder(
                    textStyle: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.2,
                      color: scheme.onSurface,
                    ),
                  ),
                ),
                Text(
                  'Label Medium ',
                  style: bodyBuilder(
                    textStyle: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w500,
                      letterSpacing: 0.2,
                      color: scheme.onSurfaceVariant,
                    ),
                  ),
                ),
                Text(
                  'Label Small',
                  style: bodyBuilder(
                    textStyle: TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w500,
                      letterSpacing: 0.3,
                      color: scheme.onSurfaceVariant,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // Numbers and data
            Text(
              '128 Episodes  ·  42 min  ·  2.4k plays',
              style: bodyBuilder(
                textStyle: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                  height: 1.5,
                  letterSpacing: 0.1,
                  color: scheme.onSurfaceVariant,
                ),
              ),
            ),
            const SizedBox(height: 12),

            // CJK text
            Text(
              '你好世界 · 个人智能助手 · 播客转录',
              style: bodyBuilder(
                textStyle: TextStyle(
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
