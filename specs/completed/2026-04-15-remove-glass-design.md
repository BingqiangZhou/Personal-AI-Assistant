# Remove Glass Effect — Design Spec

**Date:** 2026-04-15
**Status:** Approved
**Replaces:** Monochrome glass design (2026-04-15)

## Goal

Remove the entire glass/frosted-glass visual system and replace it with pure flat Material 3 styling. No BackdropFilter, no gradient orbs, no custom semi-transparent fills.

## Background

The app uses a 5-file glass design system (`core/glass/`) providing:
- `GlassBackground` — full-page gradient orbs + background color (13 pages)
- `GlassContainer` — BackdropFilter blur + semi-transparent fill (8 sheets/dialogs/notices)
- `SurfaceCard` — tier-based fill + border without blur (15+ card surfaces)
- `GlassTokens` — blur sigma and fill color resolution
- `GlassVibrancy` — text readability helpers (dead code, zero consumers)

The recent monochrome glass refactor (commits 9e4112a3..55aa5fe3) already desaturated the glass system. The user now wants to remove glass effects entirely in favor of flat Material 3.

## Design Decisions

### 1. Page Backgrounds

**Remove:** `GlassBackground` (4 gradient orbs + background color)
**Replace with:** `Scaffold` uses `ThemeData.scaffoldBackgroundColor` directly. No wrapper widget needed.

Colors remain the same:
- Dark: `#0f0f1a` (`AppColors.darkBackground`)
- Light: `#F8F9FA` (`AppColors.lightBackground`)

Affected shells (`app_shells.dart`): `ContentShell`, `ProfileShell`, `AuthShell` — remove `GlassBackground` wrapper, return body directly.

### 2. Cards and Surfaces

**Remove:** `SurfaceCard` (3-tier fill + border system)
**Replace with:** Material 3 `Card` widget or plain `Container` using built-in surface colors:
- `surfaceContainerLowest` (was `surface` tier, lightest)
- `surfaceContainerLow` (was `card` tier)
- `surfaceContainer` (was `elevated` tier)

**Remove:** `GlassContainer` (BackdropFilter blur + fill)
**Replace with:** `Container` with `surfaceContainerHighest` color + appropriate `BorderRadius`.

Affected helpers:
- `adaptive_sheet_helper.dart` — bottom sheets use `Container(color: surfaceContainerHighest)` with rounded corners
- `glass_dialog_helper.dart` — dialogs use standard `AlertDialog` surface styling
- `top_floating_notice.dart` — toast uses `Container` with surface color

### 3. Direct Token Usage

Two pages reference `GlassTokens.of(context).glassFill` directly for button/chip backgrounds:
- `podcast_daily_report_page.dart` (3 occurrences)
- `podcast_highlights_page.dart` (1 occurrence)

**Replace with:** `Theme.of(context).colorScheme.surfaceContainerHighest` or appropriate surface color.

### 4. Cleanup

**Delete entirely:**
- `frontend/lib/core/glass/` directory (5 files, 532 lines)
- `frontend/test/unit/core/glass/` — `glass_tokens_test.dart`, `glass_vibrancy_test.dart`
- `frontend/test/widget/core/glass/` — `glass_background_test.dart`, `glass_container_test.dart`

**Modify `app_colors.dart`:**
- Remove 6 tier token properties from `AppThemeExtension`: `surfaceTierFill`, `cardTierFill`, `elevatedTierFill`, `surfaceTierBorder`, `cardTierBorder`, `elevatedTierBorder`
- Remove corresponding color constants (12 values: 6 dark + 6 light)

**Update CLAUDE.md:**
- Remove `core/glass/` from project structure
- Remove Arc+Linear design system references from conventions
- Remove glass-related gotchas

## Affected Files (29 consumers + 5 glass files + 4 tests = 38 total)

### Core widgets (4 files)
- `app_shells.dart` — remove `GlassBackground` wrapper
- `adaptive_sheet_helper.dart` — `GlassContainer` → `Container`
- `glass_dialog_helper.dart` — `GlassContainer` → `Container`
- `top_floating_notice.dart` — `GlassContainer` → `Container`

### Podcast feature (10 files)
- `podcast_episode_detail_page.dart` — remove `GlassBackground`, replace `GlassContainer`
- `podcast_episode_detail_page_content.dart` — replace `GlassContainer`
- `podcast_highlights_page.dart` — remove `GlassBackground`, replace `GlassTokens` direct usage
- `podcast_daily_report_page.dart` — remove `GlassBackground`, replace `GlassTokens` direct usage
- `podcast_episodes_page.dart` — remove `GlassBackground`
- `podcast_downloads_page.dart` — remove `GlassBackground`, replace `SurfaceCard`
- `add_podcast_dialog.dart` — `GlassContainer` → `Container`
- `podcast_bottom_player_widget.dart` — `GlassContainer` → `Container`
- `podcast_bottom_player_layouts.dart` — replace `GlassContainer`
- `base_episode_card.dart` — `SurfaceCard` → `Card`
- `highlight_card.dart` — `SurfaceCard` → `Card`
- `highlight_detail_sheet.dart` — `SurfaceCard` → `Card`
- `transcription_status_widget.dart` — `SurfaceCard` → `Card`
- `transcript_result_widget.dart` — `SurfaceCard` → `Card`

### Auth feature (3 files)
- `auth_verify_page.dart` — remove `GlassBackground`, replace `SurfaceCard`
- `onboarding_page.dart` — remove `GlassBackground`
- `register_page.dart` — `SurfaceCard` → `Card`

### Profile feature (4 files)
- `terms_page.dart` — remove `GlassBackground`
- `privacy_page.dart` — remove `GlassBackground`
- `profile_subscriptions_page.dart` — remove `GlassBackground`, replace `SurfaceCard`
- `profile_history_page.dart` — remove `GlassBackground`, replace `SurfaceCard`
- `profile_cache_management_page.dart` — remove `GlassBackground`, replace `SurfaceCard`

### Settings feature (1 file)
- `font_combo_card.dart` — `SurfaceCard` → `Card`

### Shared (1 file)
- `settings_section_card.dart` — `SurfaceCard` → `Card`

### Theme/config
- `app_colors.dart` — remove tier tokens from `AppThemeExtension`
- `CLAUDE.md` — update structure and conventions

## Migration Pattern

For each consumer file, the replacement follows a consistent pattern:

**GlassBackground removal:**
```dart
// Before
GlassBackground(child: Scaffold(body: content))
// After
Scaffold(body: content)  // scaffoldBackgroundColor already set in theme
```

**SurfaceCard replacement:**
```dart
// Before
SurfaceCard(tier: CardTier.card, borderRadius: 14, child: content)
// After
Card(child: content)  // or Container with surfaceContainer color
```

**GlassContainer replacement:**
```dart
// Before
GlassContainer(tier: GlassTier.standard, borderRadius: 14, child: content)
// After
Container(
  decoration: BoxDecoration(
    color: colorScheme.surfaceContainerHighest,
    borderRadius: BorderRadius.circular(14),
  ),
  child: content,
)
```

## Testing

- Delete 4 existing glass test files
- Existing widget tests for pages that used glass components should still pass after migration
- Run `flutter test` to verify no compilation or runtime errors
- Visual verification: no backdrop blur, no gradient orbs, clean flat surfaces
