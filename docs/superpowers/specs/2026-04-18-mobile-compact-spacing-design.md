# Mobile Compact Spacing Design

## Goal

Make mobile pages (~35% tighter) by introducing a responsive spacing system with compact and standard token sets, while keeping tablet/desktop spacing unchanged.

## Current State

`AppSpacing` is a class of static const doubles (4-point grid scale). All 86 files across the app use the same fixed values regardless of screen size. `ResponsiveHelpers` exists but is barely used (4 calls from theme only).

## Design

### 1. AppSpacingData class

New instance-based spacing class in `app_spacing.dart`:

```dart
class AppSpacingData {
  final double xxs, xs, sm, smMd, md, mdLg, lg, xl, xxl;
  const AppSpacingData({
    required this.xxs, required this.xs, required this.sm,
    required this.smMd, required this.md, required this.mdLg,
    required this.lg, required this.xl, required this.xxl,
  });

  static const standard = AppSpacingData(
    xxs: 2, xs: 4, sm: 8, smMd: 12, md: 16, mdLg: 20, lg: 24, xl: 32, xxl: 48,
  );

  static const compact = AppSpacingData(
    xxs: 1, xs: 3, sm: 6, smMd: 8, md: 12, mdLg: 14, lg: 16, xl: 20, xxl: 28,
  );
}
```

Token mapping:

| Token | standard | compact | Reduction |
|-------|----------|---------|-----------|
| xxs   | 2        | 1       | -50%      |
| xs    | 4        | 3       | -25%      |
| sm    | 8        | 6       | -25%      |
| smMd  | 12       | 8       | -33%      |
| md    | 16       | 12      | -25%      |
| mdLg  | 20       | 14      | -30%      |
| lg    | 24       | 16      | -33%      |
| xl    | 32       | 20      | -38%      |
| xxl   | 48       | 28      | -42%      |

### 2. Context extension

```dart
extension SpacingExtension on BuildContext {
  AppSpacingData get spacing =>
    MediaQuery.sizeOf(this).width < Breakpoints.medium
      ? AppSpacingData.compact
      : AppSpacingData.standard;
}
```

Mobile (<600px) gets compact values; everything else gets standard.

### 3. Backward compatibility

Keep `AppSpacing` class with existing static const values unchanged. Files not yet migrated continue to work. Migration replaces `AppSpacing.xxx` with `context.spacing.xxx` one file at a time.

### 4. Full migration

Replace all `AppSpacing.xxx` references (741 occurrences across 86 files) with `context.spacing.xxx`. The existing `AppSpacing` class is kept but no longer referenced by feature code.

Migration pattern:
- `AppSpacing.md` -> `context.spacing.md`
- Ensure `context` is available in scope (it already is in all build methods and most helper methods)
- For static contexts where `BuildContext` is unavailable (e.g., const constructors, theme definitions), keep `AppSpacing.standard.xxx`

### 5. ResponsiveHelpers update

Update `ResponsiveHelpers` to use the new system internally, or deprecate in favor of `context.spacing`.

## Files Changed

### New/modified core files
- `core/constants/app_spacing.dart` - add `AppSpacingData`, `SpacingExtension`
- `core/theme/responsive_helpers.dart` - update to use new system

### Migrated feature files (all 86 files)
All files currently importing `app_spacing.dart` will switch from `AppSpacing.xxx` to `context.spacing.xxx`.

## Testing

- Widget tests for all modified pages must pass
- Visual verification on mobile (<600px) to confirm compact layout
- Visual verification on tablet/desktop to confirm no change
- Verify `const` constructors that reference `AppSpacing` still compile (they use `AppSpacing.standard`)

## Out of Scope

- Changing hardcoded spacing values in theme definitions (`app_theme.dart` widget themes) — these are Material/Cupertino framework conventions
- Changing `AppRadius` or `AppColors` tokens
- Modifying responsive breakpoint values
