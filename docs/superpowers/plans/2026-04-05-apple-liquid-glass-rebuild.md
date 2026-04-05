# Apple Liquid Glass Three-Layer Architecture Rebuild

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rebuild the frontend glass system following Apple's three-layer architecture (content/navigation/overlay), replace custom colors with Apple HIG standard colors, and fix all text readability issues.

**Architecture:** Three layers — content (SurfaceCard, opaque), navigation (GlassContainer, medium/heavy), overlay (GlassContainer, ultraHeavy). Apple system colors replace all custom accent colors. Glass tokens realigned to Apple Liquid Glass spec.

**Tech Stack:** Flutter 3.8+, Dart, Material 3, existing Riverpod/go_router stack.

**Spec:** `docs/superpowers/specs/2026-04-05-apple-liquid-glass-rebuild-design.md`

---

## Phase 1: Foundation — Apple Colors + SurfaceCard + Vibrancy

### Task 1.1: Create Apple System Colors

**Files:**
- Create: `lib/core/theme/apple_colors.dart`
- Create: `test/unit/core/theme/apple_colors_test.dart`

- [ ] **Step 1:** Create `apple_colors.dart` with all Apple HIG system colors (light + dark variants for labels, fills, backgrounds, separators, tint colors, gray scale). Reference spec section 3 for exact hex values.

- [ ] **Step 2:** Create unit test verifying all colors have correct hex values for both modes.

- [ ] **Step 3:** Run `flutter test test/unit/core/theme/apple_colors_test.dart` — expected PASS.

- [ ] **Step 4:** Commit: `feat(theme): add Apple HIG system color definitions`

### Task 1.2: Update AppColors to Use Apple Colors

**Files:**
- Modify: `lib/core/theme/app_colors.dart`
- Modify: `test/unit/core/theme/app_colors_test.dart` (if exists)
- Modify: `lib/core/theme/app_theme.dart`

- [ ] **Step 1:** In `app_colors.dart`, replace background colors with Apple values:
  - `lightBackground` → `#F2F2F7` (systemGroupedBackground)
  - `darkBackground` → `#000000` (systemGroupedBackground dark)
  - `lightSurface` → `#FFFFFF` (secondarySystemGroupedBackground)
  - `darkSurface` → `#1C1C1E` (secondarySystemGroupedBackground dark)
  - Text colors → Apple label colors
  - Outline colors → Apple separator/fill colors

- [ ] **Step 2:** Replace accent colors with Apple system tint colors:
  - `primary` → `systemIndigo` light `#5856D6` / dark `#5E5CE6`
  - `accentWarm` → `systemOrange` light `#FF9500` / dark `#FF9F0A`
  - `sunGlow` → `systemYellow` light `#FFCC00` / dark `#FFD60A`
  - `accentCoral` → `systemPink` light `#FF2D55` / dark `#FF375F`
  - `leaf` → `systemGreen` light `#34C759` / dark `#30D158`
  - `error` → `systemRed` light `#FF3B30` / dark `#FF453A`

- [ ] **Step 3:** Update `app_theme.dart` scaffold background to use new Apple background values.

- [ ] **Step 4:** Run `flutter test` — fix any broken tests.

- [ ] **Step 5:** Commit: `refactor(theme): migrate to Apple HIG color system`

### Task 1.3: Create SurfaceCard Widget

**Files:**
- Create: `lib/core/glass/surface_card.dart`
- Create: `test/widget/core/glass/surface_card_test.dart`

- [ ] **Step 1:** Create `SurfaceCard` — opaque container using Apple `secondarySystemGroupedBackground`, subtle border from `tertiarySystemFill`, no BackdropFilter. Three variants: `normal`, `elevated`, `flat`.

- [ ] **Step 2:** Write widget tests: renders in light/dark mode, all variants, with/without padding, with child content.

- [ ] **Step 3:** Run `flutter test test/widget/core/glass/surface_card_test.dart` — expected PASS.

- [ ] **Step 4:** Commit: `feat(glass): add SurfaceCard for content layer`

### Task 1.4: Create GlassVibrancy Utility

**Files:**
- Create: `lib/core/glass/glass_vibrancy.dart`
- Create: `test/unit/core/glass/glass_vibrancy_test.dart`

- [ ] **Step 1:** Create `GlassVibrancy` with static methods `primaryText()`, `secondaryText()`, `tertiaryText()` that return Apple label colors with alpha adjusted per glass tier.

- [ ] **Step 2:** Write unit tests verifying correct color output per tier and brightness.

- [ ] **Step 3:** Run `flutter test test/unit/core/glass/glass_vibrancy_test.dart` — expected PASS.

- [ ] **Step 4:** Commit: `feat(glass): add GlassVibrancy text readability utility`

---

## Phase 2: Glass Token Realignment

### Task 2.1: Update Glass Tokens

**Files:**
- Modify: `lib/core/glass/glass_tokens.dart`
- Modify: `test/unit/core/glass/glass_tokens_test.dart`
- Modify: `test/unit/core/glass/glass_style_test.dart`

- [ ] **Step 1:** Update `_DarkGlassTokens` and `_LightGlassTokens` with spec section 4 values:
  - Uniform saturationBoost: 1.8
  - Lower fill opacities (5-10% dark, 3-8% light)
  - Uniform Fresnel borders: top 40%, bottom 10%
  - Lower noise: 0.03-0.04
  - Lower contentScrim values

- [ ] **Step 2:** Update all token test expectations to match new values.

- [ ] **Step 3:** Update glass_style_test.dart expectations to match new token values.

- [ ] **Step 4:** Run `flutter test test/unit/core/glass/` — expected PASS.

- [ ] **Step 5:** Commit: `refactor(glass): realign tokens to Apple Liquid Glass spec`

### Task 2.2: Update GlassBackground Base Colors

**Files:**
- Modify: `lib/core/glass/glass_background.dart`
- Modify: `test/widget/core/glass/glass_background_test.dart`

- [ ] **Step 1:** Update base colors: dark `#0A0A0F` → `#000000`, light `#F0F0F5` → `#F2F2F7`.

- [ ] **Step 2:** Update test expectations for new base colors.

- [ ] **Step 3:** Run `flutter test test/widget/core/glass/glass_background_test.dart` — expected PASS.

- [ ] **Step 4:** Commit: `refactor(glass): update background to Apple system colors`

---

## Phase 3: Migrate Content Layer (GlassContainer.light → SurfaceCard)

Migrate all 15 consumer files (20 usages) from `GlassContainer(tier: GlassTier.light)` to `SurfaceCard`.

### Task 3.1: Migrate Shared/Core Widgets

**Files:**
- Modify: `lib/shared/widgets/settings_section_card.dart`
- Modify: `lib/core/widgets/top_floating_notice.dart`
- Modify: `lib/core/widgets/app_shells.dart` (the `AnimatedPanel` widget)

- [ ] **Step 1:** Replace `GlassContainer(tier: GlassTier.light, ...)` with `SurfaceCard(...)` in each file. Map parameters: `borderRadius` → `borderRadius`, `padding` → `padding`, `child` → `child`. Remove glass-specific params (`animate`, `interactive`, `tint` — handle `tint` as background color override).

- [ ] **Step 2:** Run `flutter test` — fix any failures.

- [ ] **Step 3:** Commit: `refactor: migrate shared/core widgets to SurfaceCard`

### Task 3.2: Migrate Auth Feature Widgets

**Files:**
- Modify: `lib/features/auth/presentation/pages/register_page.dart`
- Modify: `lib/features/auth/presentation/pages/auth_verify_page.dart`
- Modify: `lib/features/auth/presentation/widgets/password_requirement_item.dart`

- [ ] **Step 1:** Replace all `GlassContainer(tier: GlassTier.light, ...)` with `SurfaceCard(...)`.

- [ ] **Step 2:** Run `flutter test` — fix failures.

- [ ] **Step 3:** Commit: `refactor(auth): migrate glass to SurfaceCard`

### Task 3.3: Migrate Profile Feature Pages

**Files:**
- Modify: `lib/features/profile/presentation/pages/profile_subscriptions_page.dart`
- Modify: `lib/features/profile/presentation/pages/profile_history_page.dart`
- Modify: `lib/features/profile/presentation/pages/profile_cache_management_page.dart`

- [ ] **Step 1:** Replace all `GlassContainer(tier: GlassTier.light, ...)` with `SurfaceCard(...)`.

- [ ] **Step 2:** Run `flutter test` — fix failures.

- [ ] **Step 3:** Commit: `refactor(profile): migrate glass to SurfaceCard`

### Task 3.4: Migrate Podcast Feature Pages

**Files:**
- Modify: `lib/features/podcast/presentation/pages/podcast_daily_report_page.dart`
- Modify: `lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart`
- Modify: `lib/features/podcast/presentation/pages/podcast_highlights_page.dart`

- [ ] **Step 1:** Replace all `GlassContainer(tier: GlassTier.light, ...)` with `SurfaceCard(...)`.

- [ ] **Step 2:** Run `flutter test` — fix failures.

- [ ] **Step 3:** Commit: `refactor(podcast): migrate podcast pages to SurfaceCard`

### Task 3.5: Migrate Podcast Feature Widgets

**Files:**
- Modify: `lib/features/podcast/presentation/widgets/shared/base_episode_card.dart`
- Modify: `lib/features/podcast/presentation/widgets/highlight_card.dart`
- Modify: `lib/features/podcast/presentation/widgets/highlight_detail_sheet.dart`
- Modify: `lib/features/podcast/presentation/widgets/transcription_status_widget.dart`
- Modify: `lib/features/settings/presentation/widgets/font_combo_card.dart`

- [ ] **Step 1:** Replace all `GlassContainer(tier: GlassTier.light, ...)` with `SurfaceCard(...)`.

- [ ] **Step 2:** Run `flutter test` — fix failures.

- [ ] **Step 3:** Commit: `refactor(podcast): migrate podcast widgets to SurfaceCard`

---

## Phase 4: Fix Accent Color Usage (11 files, 35 replacements)

Replace all custom accent color references with Apple system colors.

### Task 4.1: Fix Podcast Accent Colors

**Files:**
- Modify: `lib/features/podcast/presentation/widgets/highlight_score_indicator.dart`
- Modify: `lib/features/podcast/presentation/widgets/highlight_card.dart`
- Modify: `lib/features/podcast/presentation/widgets/highlight_detail_sheet.dart`
- Modify: `lib/features/podcast/presentation/widgets/discover/discover_chart_row.dart`

- [ ] **Step 1:** Replace accent colors:
  - `AppColors.indigo` → `AppleColors.systemIndigo(context)`
  - `AppColors.accentWarm` → `AppleColors.systemOrange(context)`
  - `AppColors.accentCoral` → `AppleColors.systemPink(context)`
  - `AppColors.sunGlow` → `AppleColors.systemYellow(context)`
  - `AppColors.leaf` → `AppleColors.systemGreen(context)`
  - `Colors.red` → `AppleColors.systemRed(context)`
  - `AppColors.sunRay` → `AppleColors.systemRed(context)` (error-like)

- [ ] **Step 2:** Update score color thresholds to use Apple colors per spec section 8.

- [ ] **Step 3:** Run `flutter test` — fix failures.

- [ ] **Step 4:** Commit: `refactor(podcast): use Apple system colors for scores and highlights`

### Task 4.2: Fix Auth + Core Accent Colors

**Files:**
- Modify: `lib/features/auth/presentation/pages/auth_verify_page.dart`
- Modify: `lib/features/auth/presentation/pages/onboarding_page.dart`
- Modify: `lib/features/auth/presentation/pages/forgot_password_page.dart`
- Modify: `lib/features/auth/presentation/pages/reset_password_page.dart`
- Modify: `lib/features/auth/presentation/widgets/password_requirement_item.dart`
- Modify: `lib/core/widgets/page_transitions.dart`
- Modify: `lib/core/widgets/custom_adaptive_navigation.dart`

- [ ] **Step 1:** Replace all `AppColors.accentWarm` → `AppleColors.systemOrange(context)`, `Colors.red` → `AppleColors.systemRed(context)`, `AppColors.accentCoral` → `AppleColors.systemPink(context)`.

- [ ] **Step 2:** Run `flutter test` — fix failures.

- [ ] **Step 3:** Commit: `refactor: use Apple system colors across auth and core widgets`

---

## Phase 5: Glass Interactive Enhancements

### Task 5.1: Add Shimmer Effect to GlassContainer Hover

**Files:**
- Modify: `lib/core/glass/glass_container.dart`
- Modify: `test/widget/core/glass/glass_container_test.dart`

- [ ] **Step 1:** Add a `_ShimmerPainter` that draws a 30° white gradient sweep (alpha 8%, 400ms duration) triggered on mouse enter in the hover state.

- [ ] **Step 2:** Integrate shimmer into the `_buildLayer4Dynamic` method, activated by `_hoverController`.

- [ ] **Step 3:** Add widget test verifying shimmer animation controller starts on hover.

- [ ] **Step 4:** Run `flutter test test/widget/core/glass/glass_container_test.dart` — expected PASS.

- [ ] **Step 5:** Commit: `feat(glass): add shimmer effect on hover`

### Task 5.2: Add Spring Bounce to GlassContainer Press

**Files:**
- Modify: `lib/core/glass/glass_container.dart`

- [ ] **Step 1:** Replace `AnimatedScale(scale: _isPressed ? 0.98 : 1.0, duration: 100ms, curve: Curves.easeOut)` with spring-based animation using a custom `SpringSimulation` (response: 0.3, dampingFraction: 0.6). Press → scale to 0.98, release → bounce back to 1.0.

- [ ] **Step 2:** Run `flutter test` — expected PASS.

- [ ] **Step 3:** Commit: `feat(glass): add spring bounce animation on press`

### Task 5.3: Add Materialize Entry Animation

**Files:**
- Modify: `lib/core/glass/glass_container.dart`

- [ ] **Step 1:** Enhance existing `_entryController` to apply both opacity 0→1 and scale 0.95→1.0 over 200ms with `Curves.easeOutCubic`.

- [ ] **Step 2:** Run `flutter test` — expected PASS.

- [ ] **Step 3:** Commit: `feat(glass): add materialize entry animation`

---

## Phase 6: Verification + Cleanup

### Task 6.1: Full Test Suite + Build Runner

- [ ] **Step 1:** Run `flutter test` — all tests must pass.
- [ ] **Step 2:** Run `dart run build_runner build` — must succeed.
- [ ] **Step 3:** Verify no remaining `GlassTier.light` usage in content-layer files via `grep -r "GlassTier.light" lib/`.
- [ ] **Step 4:** Verify no remaining `Colors.red` or old accent colors in feature files via grep.
- [ ] **Step 5:** Fix any remaining issues.
- [ ] **Step 6:** Final commit: `chore: verify Apple Liquid Glass migration complete`

---

## File Structure Summary

### New Files (4)
| File | Responsibility |
|------|---------------|
| `lib/core/theme/apple_colors.dart` | Apple HIG color definitions |
| `lib/core/glass/surface_card.dart` | Content layer opaque card |
| `lib/core/glass/glass_vibrancy.dart` | Text color utility for glass |
| Tests for each new file | |

### Modified Core Files (6)
| File | Change |
|------|--------|
| `lib/core/theme/app_colors.dart` | Apple color values |
| `lib/core/theme/app_theme.dart` | Apple backgrounds in theme |
| `lib/core/glass/glass_tokens.dart` | New token values |
| `lib/core/glass/glass_background.dart` | Apple base colors |
| `lib/core/glass/glass_container.dart` | Shimmer, spring, materialize |
| `lib/core/glass/glass_painter.dart` | Updated Fresnel values (via tokens) |

### Migrated Feature Files (15 content → SurfaceCard)
| File | Layer Change |
|------|-------------|
| `lib/shared/widgets/settings_section_card.dart` | Glass → SurfaceCard |
| `lib/core/widgets/top_floating_notice.dart` | Glass → SurfaceCard |
| `lib/core/widgets/app_shells.dart` | Glass → SurfaceCard |
| `lib/features/auth/presentation/pages/register_page.dart` | Glass → SurfaceCard |
| `lib/features/auth/presentation/pages/auth_verify_page.dart` | Glass → SurfaceCard |
| `lib/features/profile/presentation/pages/profile_subscriptions_page.dart` | Glass → SurfaceCard |
| `lib/features/profile/presentation/pages/profile_history_page.dart` | Glass → SurfaceCard |
| `lib/features/profile/presentation/pages/profile_cache_management_page.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/pages/podcast_daily_report_page.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/pages/podcast_highlights_page.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/widgets/shared/base_episode_card.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/widgets/highlight_card.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/widgets/highlight_detail_sheet.dart` | Glass → SurfaceCard |
| `lib/features/podcast/presentation/widgets/transcription_status_widget.dart` | Glass → SurfaceCard |
| `lib/features/settings/presentation/widgets/font_combo_card.dart` | Glass → SurfaceCard |

### Accent Color Fix Files (11)
| File | Colors Replaced |
|------|----------------|
| `lib/features/podcast/presentation/widgets/highlight_score_indicator.dart` | indigo, accentWarm, accentCoral |
| `lib/features/podcast/presentation/widgets/highlight_card.dart` | leaf, sunGlow |
| `lib/features/podcast/presentation/widgets/highlight_detail_sheet.dart` | leaf, sunRay, Colors.red |
| `lib/features/podcast/presentation/widgets/discover/discover_chart_row.dart` | accentWarm |
| `lib/features/auth/presentation/pages/auth_verify_page.dart` | accentWarm, Colors.red |
| `lib/features/auth/presentation/pages/onboarding_page.dart` | accentWarm, accentCoral |
| `lib/features/auth/presentation/pages/forgot_password_page.dart` | accentWarm |
| `lib/features/auth/presentation/pages/reset_password_page.dart` | accentWarm |
| `lib/features/auth/presentation/widgets/password_requirement_item.dart` | accentWarm |
| `lib/core/widgets/page_transitions.dart` | accentWarm |
| `lib/core/widgets/custom_adaptive_navigation.dart` | accentWarm |
