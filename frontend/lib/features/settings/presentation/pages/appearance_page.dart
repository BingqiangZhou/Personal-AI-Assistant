import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:personal_ai_assistant/core/localization/app_localizations_extension.dart';
import 'package:personal_ai_assistant/core/theme/font_combination.dart';
import 'package:personal_ai_assistant/core/theme/font_provider.dart';
import 'package:personal_ai_assistant/core/theme/theme_provider.dart';
import 'package:personal_ai_assistant/core/widgets/responsive_dialog_helper.dart';
import 'package:personal_ai_assistant/core/widgets/top_floating_notice.dart';
import 'package:personal_ai_assistant/features/settings/presentation/widgets/font_combo_card.dart';

/// Unified Appearance settings page combining theme mode and font selection.
class AppearancePage extends ConsumerWidget {
  const AppearancePage({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;

    return Scaffold(
      appBar: AppBar(title: Text(l10n.appearance_title)),
      body: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        children: [
          // Theme Mode Section
          _ThemeModeSection(),
          const SizedBox(height: 32),

          // Font Selection Section
          Text(
            l10n.appearance_font_section,
            style: Theme.of(context).textTheme.titleMedium?.copyWith(
                  fontWeight: FontWeight.w600,
                ),
          ),
          const SizedBox(height: 4),
          Text(
            l10n.appearance_font_section_subtitle,
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 16),
          const _FontDropdown(),
          const SizedBox(height: 16),
          const _FontPreview(),
          const SizedBox(height: 32),
        ],
      ),
    );
  }
}

/// Theme mode selection with SegmentedButton.
class _ThemeModeSection extends ConsumerWidget {
  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = context.l10n;
    final currentCode = ref.watch(themeModeCodeProvider);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          l10n.appearance_theme_section,
          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                fontWeight: FontWeight.w600,
              ),
        ),
        const SizedBox(height: 4),
        Text(
          l10n.theme_mode_subtitle,
          style: Theme.of(context).textTheme.bodySmall,
        ),
        const SizedBox(height: 16),
        SegmentedButton<String>(
          key: const Key('appearance_theme_segmented_button'),
          style: ResponsiveDialogHelper.segmentedButtonStyle(context),
          segments: [
            ButtonSegment(
              value: kThemeModeSystem,
              label: Text(l10n.theme_mode_follow_system),
              icon: const Icon(Icons.brightness_auto),
            ),
            ButtonSegment(
              value: kThemeModeLight,
              label: Text(l10n.theme_mode_light),
              icon: const Icon(Icons.light_mode),
            ),
            ButtonSegment(
              value: kThemeModeDark,
              label: Text(l10n.theme_mode_dark),
              icon: const Icon(Icons.dark_mode),
            ),
          ],
          selected: {currentCode},
          onSelectionChanged: (selection) async {
            final value = selection.first;
            final modeName = switch (value) {
              kThemeModeSystem => l10n.theme_mode_follow_system,
              kThemeModeLight => l10n.theme_mode_light,
              _ => l10n.theme_mode_dark,
            };
            await ref
                .read(themeModeProvider.notifier)
                .setThemeModeCode(value);
            if (context.mounted) {
              showTopFloatingNotice(
                context,
                message: l10n.theme_mode_changed(modeName),
              );
            }
          },
        ),
      ],
    );
  }
}

/// Dropdown selector for font combinations with a reset button.
///
/// Uses a [TextEditingController] to keep the displayed text in sync
/// when the font combination changes externally (e.g. reset, persistence load).
class _FontDropdown extends ConsumerStatefulWidget {
  const _FontDropdown();

  @override
  ConsumerState<_FontDropdown> createState() => _FontDropdownState();
}

class _FontDropdownState extends ConsumerState<_FontDropdown> {
  late TextEditingController _controller;

  @override
  void initState() {
    super.initState();
    final combo = ref.read(fontCombinationProvider);
    _controller = TextEditingController(text: combo.displayName);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final selectedCombo = ref.watch(fontCombinationProvider);
    final l10n = context.l10n;
    final scheme = Theme.of(context).colorScheme;
    final isDefault =
        selectedCombo.id == FontCombination.defaultCombination.id;

    // Keep controller in sync when the provider value changes externally.
    if (_controller.text != selectedCombo.displayName) {
      _controller.text = selectedCombo.displayName;
    }

    return IntrinsicHeight(
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Expanded(
            child: DropdownMenu<String>(
              key: const Key('appearance_font_dropdown'),
              controller: _controller,
              initialSelection: selectedCombo.id,
              width: double.infinity,
              menuHeight: 360,
              inputDecorationTheme: InputDecorationTheme(
                filled: true,
                fillColor: Colors.transparent,
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide(color: scheme.outlineVariant),
                ),
                enabledBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide(color: scheme.outlineVariant),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(12),
                  borderSide: BorderSide(color: scheme.primary, width: 2),
                ),
                contentPadding:
                    const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
              ),
              onSelected: (value) async {
                if (value == null) return;
                await ref
                    .read(fontCombinationProvider.notifier)
                    .setFontCombination(value);
                if (context.mounted) {
                  showTopFloatingNotice(
                    context,
                    message: l10n.appearance_changed,
                  );
                }
              },
              dropdownMenuEntries: FontCombination.all
                  .map(
                    (combo) => DropdownMenuEntry<String>(
                      value: combo.id,
                      label: combo.displayName,
                      style: ButtonStyle(
                        textStyle: WidgetStatePropertyAll(
                          tryGetFont(
                            combo.bodyFontFamily,
                            TextStyle(
                              fontSize: 14,
                              fontWeight: FontWeight.w500,
                              color: scheme.onSurface,
                            ),
                          ),
                        ),
                      ),
                    ),
                  )
                  .toList(),
            ),
          ),
          const SizedBox(width: 8),
          // Reset to default button
          Tooltip(
            message: l10n.appearance_font_reset,
            child: OutlinedButton(
              onPressed: isDefault
                  ? null
                  : () async {
                      await ref
                          .read(fontCombinationProvider.notifier)
                          .resetToDefault();
                      if (context.mounted) {
                        showTopFloatingNotice(
                          context,
                          message: l10n.appearance_changed,
                        );
                      }
                    },
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(12),
                ),
                side: BorderSide(
                  color: isDefault
                      ? scheme.outlineVariant
                      : scheme.outline,
                ),
              ),
              child: Icon(
                Icons.refresh,
                size: 20,
                color: isDefault
                    ? scheme.outlineVariant
                    : scheme.onSurfaceVariant,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

/// Font preview card that shows the selected font combination specimen.
class _FontPreview extends ConsumerWidget {
  const _FontPreview();

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final selectedCombo = ref.watch(fontCombinationProvider);
    return FontComboCard(combo: selectedCombo);
  }
}
