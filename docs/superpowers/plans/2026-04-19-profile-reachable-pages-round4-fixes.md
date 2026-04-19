# Profile Reachable Pages Round 4 Fixes — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 20 remaining issues in profile-reachable pages — bugs, UX, dead code, i18n, mounted checks.

**Architecture:** Fix issues file-by-file, grouping related changes into single commits.

**Tech Stack:** Flutter 3.8+, Dart, Riverpod

## Files Modified

| File | Issues |
|------|--------|
| `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart` | 1.1, 3.1, 3.4 |
| `frontend/lib/features/podcast/presentation/widgets/conversation_chat_widget.dart` | 1.2, 2.1 |
| `frontend/lib/features/settings/presentation/widgets/update_dialog.dart` | 1.3, 2.2, 4.1, 4.2 |
| `frontend/lib/shared/widgets/server_config_dialog.dart` | 1.4, 4.3 |
| `frontend/lib/features/podcast/presentation/providers/podcast_core_providers.dart` | 1.5 |
| `frontend/lib/features/settings/presentation/pages/appearance_page.dart` | 2.3 |
| `frontend/lib/features/podcast/presentation/widgets/add_podcast_dialog.dart` | 2.4, 2.5 |
| `frontend/lib/features/podcast/presentation/pages/podcast_episodes_page.dart` | 3.2, 3.3 |
| `frontend/lib/features/profile/presentation/pages/profile_page.dart` | 5.1, 5.2, 5.3 |

---

## Task 1: Fix _summaryUpdateScheduled reset + dead imports + stub method in episode detail (Spec 1.1, 3.1, 3.4)

**File:** `frontend/lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart`

### 1.1 — Reset _summaryUpdateScheduled in didUpdateWidget

In `didUpdateWidget`, find where `_selectedSummaryText = '';` is reset (around line 362). Add after it:
```dart
      _summaryUpdateScheduled = false;
```

### 3.1 — Remove unused imports

Remove these 3 imports:
- Line 15: `import 'package:personal_ai_assistant/core/theme/app_colors.dart';`
- Line 20: `import 'package:personal_ai_assistant/core/widgets/app_shells.dart';`
- Line 21: `import 'package:personal_ai_assistant/core/widgets/custom_adaptive_navigation.dart';`

### 3.4 — Clean up stub _updateHeaderStateForTab

The method at lines 158-160 only sets `_showScrollToTopButton.value = false;` and ignores `tabIndex`. Remove the `tabIndex` parameter and update any call sites.

Steps:
- [ ] Add `_summaryUpdateScheduled = false;` in didUpdateWidget
- [ ] Remove 3 unused imports
- [ ] Remove `tabIndex` parameter from `_updateHeaderStateForTab` and update call sites
- [ ] Run: `cd frontend && flutter analyze lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart`
- [ ] Commit: `fix(podcast): reset summary guard on episode switch and remove dead imports`

---

## Task 2: Fix chat select mode reset + remove auto-share on text selection (Spec 1.2, 2.1)

**File:** `frontend/lib/features/podcast/presentation/widgets/conversation_chat_widget.dart`

### 1.2 — Reset select mode on episode change

In `didUpdateWidget` (around lines 113-126), when `episodeId` changes, add reset of select mode state. Find the block that handles episode change and add:
```dart
    _isMessageSelectMode = false;
    _selectedMessageIds.clear();
```

### 2.1 — Remove auto-share on text selection

Find `_handleTextSelected` (around lines 350-357). It currently calls `unawaited(_shareSelectedChatAsImage())`. Remove this call — text selection should not trigger sharing.

Steps:
- [ ] Add select mode reset in didUpdateWidget
- [ ] Remove auto-share call from _handleTextSelected
- [ ] Run: `cd frontend && flutter analyze lib/features/podcast/presentation/widgets/conversation_chat_widget.dart`
- [ ] Commit: `fix(podcast): reset chat select mode on episode change and remove auto-share on text selection`

---

## Task 3: Fix static _isShowing flag + no feedback on URL failure + hardcoded spacing in update dialog (Spec 1.3, 2.2, 4.1, 4.2)

**File:** `frontend/lib/features/settings/presentation/widgets/update_dialog.dart`

### 1.3 — Make _isShowing flag safe with try/finally

Find the method that sets `_isShowing = true` and calls `showAppDialog` (around line 653). Wrap in try/finally:
```dart
    _isShowing = true;
    try {
      await showAppDialog(...);
    } finally {
      _isShowing = false;
    }
```

### 2.2 — Add feedback when URL launch fails

Find the `canLaunchUrl` checks in `_handleDownload` (around lines 568-570, 600-608). When `canLaunchUrl` returns false, show a `showTopFloatingNotice` with a localized error message. Add a new ARB key `update_download_url_failed` (EN: "Could not open download link", ZH: "无法打开下载链接").

### 4.1 — Replace hardcoded SizedBox heights

Search and replace throughout the file:
- `SizedBox(height: 8)` → `SizedBox(height: context.spacing.sm)`
- `SizedBox(width: 8)` → `SizedBox(width: context.spacing.sm)`
- `SizedBox(height: 18)` → `SizedBox(height: context.spacing.lg)`
- `SizedBox(height: 10)` → `SizedBox(height: context.spacing.sm)`

Only replace instances where `context` is available (inside build methods). Skip any `const SizedBox` that can't use context.

### 4.2 — Remove raw exception from download failed message

Find line ~615: `message: '${l10n.update_download_failed}: $e'`
Replace with: `message: l10n.update_download_failed`

Steps:
- [ ] Wrap showAppDialog in try/finally for _isShowing safety
- [ ] Add feedback when canLaunchUrl returns false
- [ ] Replace hardcoded SizedBox heights with spacing tokens
- [ ] Remove raw exception from download failed message
- [ ] Add ARB key if needed, run gen-l10n
- [ ] Run: `cd frontend && flutter analyze`
- [ ] Commit: `fix(settings): improve update dialog robustness and i18n`

---

## Task 4: Fix dead code + hardcoded spacing in server config dialog (Spec 1.4, 4.3)

**File:** `frontend/lib/shared/widgets/server_config_dialog.dart`

### 1.4 — Remove duplicate iOS/non-iOS branches

Find lines 245-256. The `if (isIOS)` check has identical branches. Replace both with a single return:
```dart
    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: EdgeInsets.all(context.spacing.md),
      child: dialogChild,
    );
```

### 4.3 — Replace hardcoded vertical padding

Find line 290: `vertical: 10`
Replace with: `vertical: context.spacing.sm`

Steps:
- [ ] Remove duplicate if/else branches
- [ ] Replace hardcoded vertical padding
- [ ] Run: `cd frontend && flutter analyze lib/shared/widgets/server_config_dialog.dart`
- [ ] Commit: `refactor(settings): remove dead code and fix spacing in server config dialog`

---

## Task 5: Invalidate profile providers on server switch (Spec 1.5)

**File:** `frontend/lib/features/podcast/presentation/providers/podcast_core_providers.dart`

Find the server config listener provider (around lines 48-69). It currently invalidates some providers but misses profile-related ones. Add these invalidations:

```dart
    ref.invalidate(podcastStatsProvider);
    ref.invalidate(dailyReportProvider);
    ref.invalidate(dailyReportDatesProvider);
    ref.invalidate(highlightsProvider);
    ref.invalidate(highlightDatesProvider);
    ref.invalidate(playbackHistoryLiteProvider);
```

Find the correct provider names by checking the imports in this file and the actual provider variable names.

Steps:
- [ ] Add missing provider invalidations to server config listener
- [ ] Ensure all providers are imported
- [ ] Run: `cd frontend && flutter analyze lib/features/podcast/presentation/providers/podcast_core_providers.dart`
- [ ] Commit: `fix(podcast): invalidate profile providers on server switch`

---

## Task 6: Fix theme notification + add podcast dialog issues (Spec 2.3, 2.4, 2.5)

**Files:**
- `frontend/lib/features/settings/presentation/pages/appearance_page.dart`
- `frontend/lib/features/podcast/presentation/widgets/add_podcast_dialog.dart`

### 2.3 — Skip notification when selecting same theme

In `appearance_page.dart`, find the theme mode `onChanged` callback (around lines 102-115). Add a guard before showing the notification:

```dart
    final currentCode = ref.read(themeModeProvider).name;
    if (value == currentCode) return;
```

Or compare against the currently selected value before showing `showTopFloatingNotice`.

### 2.4 — Remove raw exception from add podcast error

In `add_podcast_dialog.dart`, find the error display (around lines 53-57). Change from showing `'${l10n.podcast_failed_add} $error'` to just `l10n.podcast_failed_add`.

### 2.5 — Improve URL validation

In `add_podcast_dialog.dart`, find the validator (around lines 111-113). Replace `value.startsWith('http')` with:
```dart
value != null && (value.startsWith('http://') || value.startsWith('https://'))
```

Steps:
- [ ] Add same-theme guard in appearance page
- [ ] Remove raw exception from add podcast error
- [ ] Improve URL validation
- [ ] Run: `cd frontend && flutter analyze`
- [ ] Commit: `fix: improve theme notification and add podcast dialog validation`

---

## Task 7: Remove dead code in episodes page (Spec 3.2, 3.3)

**File:** `frontend/lib/features/podcast/presentation/pages/podcast_episodes_page.dart`

### 3.2 — Remove unused cupertino import

Remove line 1: `import 'package:flutter/cupertino.dart';`

### 3.3 — Remove commented-out debug block

Remove lines 141-150 (the large commented-out block about first-episode image fields).

Steps:
- [ ] Remove unused import
- [ ] Remove commented-out block
- [ ] Run: `cd frontend && flutter analyze lib/features/podcast/presentation/pages/podcast_episodes_page.dart`
- [ ] Commit: `refactor(podcast): remove dead code from episodes page`

---

## Task 8: Fix mounted checks and stale l10n in profile page (Spec 5.1, 5.2, 5.3)

**File:** `frontend/lib/features/profile/presentation/pages/profile_page.dart`

### 5.1 — Add mounted guard in initState callback

Find `initState` (around lines 39-47). Inside the `addPostFrameCallback`, add `if (!mounted) return;` as the first line of the callback.

### 5.2 — Fix stale l10n in _showChangePasswordDialog

Find `_showChangePasswordDialog` (around lines 450-503). After the `mounted` check (line ~482), re-read `l10n`:
```dart
    if (!context.mounted) return;
    final l10n = context.l10n;
```
Move the original `final l10n = context.l10n;` (line 451) to only be used before the async gap (for dialog content), and re-read it after.

### 5.3 — Fix stale l10n in _showLogoutDialog

Same pattern in `_showLogoutDialog` (around lines 638-672). After the mounted check (line ~659), re-read `l10n`.

Steps:
- [ ] Add mounted guard in initState callback
- [ ] Fix stale l10n in _showChangePasswordDialog
- [ ] Fix stale l10n in _showLogoutDialog
- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_page.dart`
- [ ] Commit: `fix(profile): add mounted checks and fix stale l10n in dialogs`

---

## Task 9: Final verification

- [ ] Run: `cd frontend && flutter analyze`
- [ ] Fix any new issues
