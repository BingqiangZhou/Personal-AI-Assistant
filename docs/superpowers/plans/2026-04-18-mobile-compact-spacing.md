# Mobile Compact Spacing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make mobile pages ~35% tighter by introducing responsive spacing with compact/standard token sets, while keeping tablet/desktop unchanged.

**Architecture:** Add `AppSpacingData` class with two const instances (compact/standard). A `BuildContext` extension (`context.spacing`) returns the right set based on screen width. Migrate all 86 files from `AppSpacing.xxx` to `context.spacing.xxx`.

**Tech Stack:** Flutter/Dart, existing AppSpacing token system, Breakpoints constants

---

## File Structure

### Core files (modified)
- `frontend/lib/core/constants/app_spacing.dart` — add `AppSpacingData`, `SpacingExtension`, keep `AppSpacing` for backward compat

### Feature files (migrated, 86 files)
All files replace `AppSpacing.xxx` with `context.spacing.xxx`, drop `const` where needed, add `breakpoints.dart` import where missing.

### Grouped by area for parallel migration:

**Group A — Core widgets (2 files, 68 refs)**
- `core/widgets/app_shells.dart` (39)
- `core/widgets/custom_adaptive_navigation.dart` (29)

**Group B — Core adaptive/widgets (8 files, 24 refs)**
- `core/widgets/linear_section_header.dart` (5)
- `core/widgets/top_floating_notice.dart` (4)
- `core/widgets/app_dialog_helper.dart` (4)
- `core/widgets/adaptive/adaptive_button.dart` (5)
- `core/widgets/adaptive/adaptive_list_section.dart` (5)
- `core/widgets/adaptive/adaptive_action_sheet.dart` (2)
- `core/widgets/adaptive/adaptive_text_field.dart` (1)
- `core/widgets/adaptive/adaptive_search_bar.dart` (1)

**Group C — Shared widgets (5 files, 40 refs)**
- `shared/widgets/server_config_dialog.dart` (21)
- `shared/widgets/skeleton_widgets.dart` (13)
- `shared/widgets/loading_widget.dart` (3)
- `shared/widgets/settings_section_card.dart` (1)
- `shared/widgets/empty_state_widget.dart` (2)
- `shared/widgets/custom_text_field.dart` (1)

**Group D — Profile pages (7 files, 111 refs)**
- `profile/presentation/pages/profile_cache_management_page.dart` (31)
- `profile/presentation/pages/profile_page.dart` (22)
- `profile/presentation/pages/profile_history_page.dart` (20)
- `profile/presentation/pages/profile_subscriptions_page.dart` (12)
- `profile/presentation/pages/privacy_page.dart` (8)
- `profile/presentation/pages/terms_page.dart` (8)
- `profile/presentation/widgets/profile_activity_cards.dart` (13)

**Group E — Auth pages (5 files, 39 refs)**
- `auth/presentation/pages/auth_verify_page.dart` (11)
- `auth/presentation/pages/register_page.dart` (11)
- `auth/presentation/pages/onboarding_page.dart` (8)
- `auth/presentation/pages/reset_password_page.dart` (7)
- `auth/presentation/pages/forgot_password_page.dart` (6)
- `auth/presentation/pages/login_page.dart` (6)
- `auth/presentation/widgets/password_requirement_item.dart` (1)

**Group F — Podcast pages (12 files, 133 refs)**
- `podcast/presentation/pages/podcast_episode_detail_page_header.dart` (16)
- `podcast/presentation/pages/podcast_highlights_page.dart` (15)
- `podcast/presentation/pages/podcast_downloads_page.dart` (15)
- `podcast/presentation/pages/podcast_daily_report_page.dart` (17)
- `podcast/presentation/pages/podcast_episodes_page_view.dart` (19)
- `podcast/presentation/pages/podcast_feed_page.dart` (13)
- `podcast/presentation/pages/podcast_list_page.dart` (7)
- `podcast/presentation/pages/podcast_episode_detail_page_layout.dart` (7)
- `podcast/presentation/pages/podcast_episode_detail_page_content.dart` (4)
- `podcast/presentation/pages/podcast_episodes_page.dart` (2)
- `podcast/presentation/pages/sections/search_mode_toggle.dart` (3)
- `podcast/presentation/pages/podcast_episode_detail_page.dart` (0 — import only)
- `podcast/presentation/pages/podcast_bottom_player_widget.dart` (0 — import only)

**Group G — Podcast widgets (28 files, 287 refs)**
- `podcast/presentation/widgets/ai_summary_control_widget.dart` (24)
- `podcast/presentation/widgets/highlight_detail_sheet.dart` (25)
- `podcast/presentation/widgets/transcript_display_widget.dart` (22)
- `podcast/presentation/widgets/transcription/transcript_result_widget.dart` (23)
- `podcast/presentation/widgets/shared/base_episode_card.dart` (14)
- `podcast/presentation/widgets/podcast_bottom_player_layouts.dart` (13)
- `podcast/presentation/widgets/highlight_card.dart` (11)
- `podcast/presentation/widgets/transcription_status_widget.dart` (8)
- `podcast/presentation/widgets/conversation/chat_message_bubble.dart` (8)
- `podcast/presentation/widgets/discover/discover_chart_row.dart` (8)
- `podcast/presentation/widgets/country_selector_dropdown.dart` (7)
- `podcast/presentation/widgets/conversation/chat_header.dart` (7)
- `podcast/presentation/widgets/conversation/chat_empty_state.dart` (7)
- `podcast/presentation/widgets/add_podcast_dialog.dart` (6)
- `podcast/presentation/widgets/discover_episode_detail_sheet.dart` (6)
- `podcast/presentation/widgets/queue/queue_list_widget.dart` (6)
- `podcast/presentation/widgets/queue/queue_empty_state_widget.dart` (6)
- `podcast/presentation/widgets/playback_speed_selector_sheet.dart` (6)
- `podcast/presentation/widgets/shownotes_display_widget.dart` (6)
- `podcast/presentation/widgets/discover/discover_search_input.dart` (6)
- `podcast/presentation/widgets/podcast_search_result_card.dart` (4)
- `podcast/presentation/widgets/queue/queue_controls_widget.dart` (4)
- `podcast/presentation/widgets/sleep_timer_selector_sheet.dart` (4)
- `podcast/presentation/widgets/discover/discover_top_charts_section.dart` (4)
- `podcast/presentation/widgets/conversation/chat_messages_list.dart` (4)
- `podcast/presentation/widgets/conversation/chat_input_area.dart` (5)
- `podcast/presentation/widgets/conversation/chat_sessions_drawer.dart` (3)
- `podcast/presentation/widgets/podcast_bottom_player_controls.dart` (5)
- `podcast/presentation/widgets/podcast_empty_state.dart` (2)
- `podcast/presentation/widgets/search/podcast_search_results_list.dart` (2)
- `podcast/presentation/widgets/download_button.dart` (1)
- `podcast/presentation/widgets/simplified_episode_card.dart` (1)
- `podcast/presentation/widgets/podcast_feed_episode_card.dart` (1)
- `podcast/presentation/widgets/transcription/transcription_step_indicators.dart` (1)
- `podcast/presentation/widgets/highlight_score_indicator.dart` (2)
- `podcast/presentation/widgets/discover/discover_category_chips.dart` (3)
- `podcast/presentation/widgets/discover/discover_charts_list.dart` (3)
- `podcast/presentation/widgets/discover_show_episodes_sheet.dart` (3)
- `podcast/presentation/widgets/summary_display_widget.dart` (1)
- `podcast/presentation/services/content_image_share_service.dart` (6)

**Group H — Settings & splash (3 files, 35 refs)**
- `settings/presentation/widgets/update_dialog.dart` (22)
- `settings/presentation/pages/appearance_page.dart` (11)
- `splash/presentation/pages/splash_page.dart` (2)

**Group I — ResponsiveHelpers (1 file, 9 refs)**
- `core/theme/responsive_helpers.dart` (9)

---

## Task 1: Add AppSpacingData and SpacingExtension

**Files:**
- Modify: `frontend/lib/core/constants/app_spacing.dart`

- [ ] **Step 1: Add AppSpacingData class and SpacingExtension to app_spacing.dart**

Add after the existing `AppSpacing` class:

```dart
import 'package:flutter/widgets.dart';

import 'package:personal_ai_assistant/core/constants/breakpoints.dart';

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

  /// Standard spacing (tablet/desktop).
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

  /// Compact spacing (mobile, ~35% tighter).
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
```

Also add the `breakpoints.dart` import at the top of the file. Keep the existing `AppSpacing` class unchanged for backward compatibility.

- [ ] **Step 2: Run dart analyze to verify no errors**

Run: `cd frontend && dart analyze lib/core/constants/app_spacing.dart`
Expected: No errors

- [ ] **Step 3: Commit**

```
feat(ui): add AppSpacingData with compact/standard responsive spacing
```

---

## Task 2: Migrate core widgets (Group A, 2 files)

**Files:**
- Modify: `frontend/lib/core/widgets/app_shells.dart`
- Modify: `frontend/lib/core/widgets/custom_adaptive_navigation.dart`

**Migration rules per file:**
1. Replace all `AppSpacing.xxx` with `context.spacing.xxx` (where `context` is in scope)
2. Remove `const` keyword from widgets that now use runtime values (e.g., `const SizedBox(height: AppSpacing.md)` → `SizedBox(height: context.spacing.md)`)
3. Remove `const EdgeInsets(...)` → `EdgeInsets(...)` when AppSpacing values inside
4. Remove `import 'package:personal_ai_assistant/core/constants/app_spacing.dart';` if no remaining `AppSpacing` references
5. No need to add breakpoints import — `context.spacing` is an extension from `app_spacing.dart` itself

- [ ] **Step 1: Migrate app_shells.dart**
- [ ] **Step 2: Migrate custom_adaptive_navigation.dart**
- [ ] **Step 3: Run dart analyze on both files**

Run: `cd frontend && dart analyze lib/core/widgets/app_shells.dart lib/core/widgets/custom_adaptive_navigation.dart`
Expected: No errors

- [ ] **Step 4: Commit**

```
refactor(ui): migrate core shell widgets to responsive spacing
```

---

## Task 3: Migrate core adaptive widgets (Group B, 8 files)

**Files:**
- Modify: `frontend/lib/core/widgets/linear_section_header.dart`
- Modify: `frontend/lib/core/widgets/top_floating_notice.dart`
- Modify: `frontend/lib/core/widgets/app_dialog_helper.dart`
- Modify: `frontend/lib/core/widgets/adaptive/adaptive_button.dart`
- Modify: `frontend/lib/core/widgets/adaptive/adaptive_list_section.dart`
- Modify: `frontend/lib/core/widgets/adaptive/adaptive_action_sheet.dart`
- Modify: `frontend/lib/core/widgets/adaptive/adaptive_text_field.dart`
- Modify: `frontend/lib/core/widgets/adaptive/adaptive_search_bar.dart`

**Special case — linear_section_header.dart:**
This file has default parameter values like `this.padding = const EdgeInsets.symmetric(horizontal: AppSpacing.mdLg, ...)`. These `const` default values cannot use `context.spacing`. For these, change the default to `null` and resolve inside the build method:

```dart
// Before
this.padding = const EdgeInsets.symmetric(horizontal: AppSpacing.mdLg, vertical: AppSpacing.md)

// After
this.padding, // nullable, resolved in build()
// In build():
final effectivePadding = padding ?? EdgeInsets.symmetric(
  horizontal: context.spacing.mdLg,
  vertical: context.spacing.md,
);
```

Apply the same migration rules as Task 2.

- [ ] **Step 1: Migrate all 8 files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/core/widgets/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate core adaptive widgets to responsive spacing
```

---

## Task 4: Migrate shared widgets (Group C, 6 files)

**Files:**
- Modify: `frontend/lib/shared/widgets/server_config_dialog.dart`
- Modify: `frontend/lib/shared/widgets/skeleton_widgets.dart`
- Modify: `frontend/lib/shared/widgets/loading_widget.dart`
- Modify: `frontend/lib/shared/widgets/settings_section_card.dart`
- Modify: `frontend/lib/shared/widgets/empty_state_widget.dart`
- Modify: `frontend/lib/shared/widgets/custom_text_field.dart`

**Special cases:**
- `server_config_dialog.dart` uses `const EdgeInsets.all(AppSpacing.md)` for `insetPadding` on `Dialog` — these are dialog-level constraints. Convert to non-const with `context.spacing`.
- `skeleton_widgets.dart` has multiple `const EdgeInsets` patterns — all become non-const.

Apply standard migration rules.

- [ ] **Step 1: Migrate all 6 files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/shared/widgets/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate shared widgets to responsive spacing
```

---

## Task 5: Migrate profile pages (Group D, 7 files)

**Files:**
- Modify: `frontend/lib/features/profile/presentation/pages/profile_cache_management_page.dart`
- Modify: `frontend/lib/features/profile/presentation/pages/profile_page.dart`
- Modify: `frontend/lib/features/profile/presentation/pages/profile_history_page.dart`
- Modify: `frontend/lib/features/profile/presentation/pages/profile_subscriptions_page.dart`
- Modify: `frontend/lib/features/profile/presentation/pages/privacy_page.dart`
- Modify: `frontend/lib/features/profile/presentation/pages/terms_page.dart`
- Modify: `frontend/lib/features/profile/presentation/widgets/profile_activity_cards.dart`

Apply standard migration rules.

- [ ] **Step 1: Migrate all 7 files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/features/profile/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate profile pages to responsive spacing
```

---

## Task 6: Migrate auth pages (Group E, 7 files)

**Files:**
- Modify: `frontend/lib/features/auth/presentation/pages/auth_verify_page.dart`
- Modify: `frontend/lib/features/auth/presentation/pages/register_page.dart`
- Modify: `frontend/lib/features/auth/presentation/pages/onboarding_page.dart`
- Modify: `frontend/lib/features/auth/presentation/pages/reset_password_page.dart`
- Modify: `frontend/lib/features/auth/presentation/pages/forgot_password_page.dart`
- Modify: `frontend/lib/features/auth/presentation/pages/login_page.dart`
- Modify: `frontend/lib/features/auth/presentation/widgets/password_requirement_item.dart`

Apply standard migration rules.

- [ ] **Step 1: Migrate all 7 files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/features/auth/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate auth pages to responsive spacing
```

---

## Task 7: Migrate podcast pages (Group F, 13 files)

**Files:**
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page_header.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_highlights_page.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_downloads_page.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_daily_report_page.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_episodes_page_view.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_feed_page.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_list_page.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page_layout.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page_content.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_episodes_page.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/sections/search_mode_toggle.dart`
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart` (import-only, may need no changes)
- Modify: `frontend/lib/features/podcast/presentation/pages/podcast_bottom_player_widget.dart` (import-only, may need no changes)

For import-only files: check if `AppSpacing` is used. If not, just remove the import.

Apply standard migration rules for the rest.

- [ ] **Step 1: Migrate all 13 files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/features/podcast/presentation/pages/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate podcast pages to responsive spacing
```

---

## Task 8: Migrate podcast widgets (Group G, 40 files)

**Files:** All podcast widget files listed in Group G above.

**Special cases:**
- `content_image_share_service.dart` is a service, not a widget — check if it has `BuildContext` access before migrating. If not, keep `AppSpacing` static values.
- Widget files with `const EdgeInsets` default parameters: apply same pattern as `linear_section_header.dart` (nullable default, resolve in build).
- `transcript_result_widget.dart` has 23 refs — may need careful `const` removal.

Apply standard migration rules.

- [ ] **Step 1: Migrate all podcast widget files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/features/podcast/presentation/widgets/ lib/features/podcast/presentation/services/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate podcast widgets to responsive spacing
```

---

## Task 9: Migrate settings & splash (Group H, 3 files)

**Files:**
- Modify: `frontend/lib/features/settings/presentation/widgets/update_dialog.dart`
- Modify: `frontend/lib/features/settings/presentation/pages/appearance_page.dart`
- Modify: `frontend/lib/features/splash/presentation/pages/splash_page.dart`

**Special case — update_dialog.dart:**
Has 22 refs plus some hardcoded spacing values. Focus on `AppSpacing` → `context.spacing` migration. Hardcoded values are out of scope per the spec.

Apply standard migration rules.

- [ ] **Step 1: Migrate all 3 files**
- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/features/settings/ lib/features/splash/`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): migrate settings and splash pages to responsive spacing
```

---

## Task 10: Update ResponsiveHelpers (Group I, 1 file)

**Files:**
- Modify: `frontend/lib/core/theme/responsive_helpers.dart`

Update to use `AppSpacingData.compact` and `AppSpacingData.standard` instead of `AppSpacing` statics for mobile/desktop values.

- [ ] **Step 1: Update ResponsiveHelpers to reference AppSpacingData values**

Change mobile values from `AppSpacing.md` (16) to `AppSpacingData.compact.md` (12), etc.

- [ ] **Step 2: Run dart analyze**

Run: `cd frontend && dart analyze lib/core/theme/responsive_helpers.dart`
Expected: No errors

- [ ] **Step 3: Commit**

```
refactor(ui): update ResponsiveHelpers to use AppSpacingData
```

---

## Task 11: Full project verify

- [ ] **Step 1: Run full dart analyze**

Run: `cd frontend && dart analyze lib/`
Expected: No errors

- [ ] **Step 2: Run flutter test**

Run: `cd frontend && flutter test`
Expected: All tests pass

- [ ] **Step 3: Run build_runner if needed**

If any `.g.dart` files are affected:
Run: `cd frontend && dart run build_runner build --delete-conflicting-outputs`

- [ ] **Step 4: Verify no remaining AppSpacing references in feature code**

Run: `cd frontend && grep -r "AppSpacing\." lib/ --include="*.dart" | grep -v "app_spacing.dart" | grep -v ".g.dart"`
Expected: Zero results (all migrated to `context.spacing`)

- [ ] **Step 5: Final commit if any cleanup needed**

```
chore(ui): finalize responsive spacing migration
```

---

## Self-Review Checklist

- [x] **Spec coverage:** Every section in the spec maps to a task
- [x] **Placeholder scan:** No TBDs, TODOs, or vague steps
- [x] **Type consistency:** `AppSpacingData` class and `context.spacing` extension used consistently across all tasks
- [x] **Special cases handled:** const defaults with nullable pattern, import-only files, service without BuildContext
