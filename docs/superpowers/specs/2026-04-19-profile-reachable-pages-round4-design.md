# Profile Reachable Pages Issues — Design Spec (Round 4)

**Date:** 2026-04-19
**Scope:** Fourth audit pass — dialogs, secondary navigation, providers, chat drawer
**Preceding rounds:** Round 1 (20 issues), Round 2 (17 issues), Round 3 (14 issues)

## Category 1: Concrete Bugs

### 1.1 _summaryUpdateScheduled not reset on episode switch
**File:** `podcast_episode_detail_page.dart:~362`
**Fix:** Add `_summaryUpdateScheduled = false;` in `didUpdateWidget` alongside `_selectedSummaryText = '';`.

### 1.2 Chat select mode not reset on episode change
**File:** `conversation_chat_widget.dart:113-126`
**Fix:** In `didUpdateWidget` when `episodeId` changes, reset `_isMessageSelectMode = false` and `_selectedMessageIds.clear()`.

### 1.3 Static _isShowing flag can permanently block update dialog
**File:** `update_dialog.dart:653`
**Fix:** Wrap the `_isShowing = true` assignment and `showAppDialog` call in try/finally to ensure `_isShowing` is always reset.

### 1.4 Dead code — duplicate iOS/non-iOS branches in server config dialog
**File:** `server_config_dialog.dart:245-256`
**Fix:** Remove the `if (isIOS)` check and return the single `Dialog` widget unconditionally.

### 1.5 Server switch doesn't invalidate profile-related providers
**File:** `podcast_core_providers.dart:48-69`
**Fix:** Add `ref.invalidate()` calls for `podcastStatsProvider`, `dailyReportProvider`, `dailyReportDatesProvider`, `highlightsProvider`, `highlightDatesProvider`, and `playbackHistoryLiteProvider`.

## Category 2: UX

### 2.1 Auto-share on chat text selection
**File:** `conversation_chat_widget.dart:350-357`
**Fix:** Remove the auto-share call from `_handleTextSelected`. Text selection should not trigger sharing.

### 2.2 No feedback when URL launch fails in update dialog
**File:** `update_dialog.dart:568-570`
**Fix:** Show a SnackBar or `showTopFloatingNotice` with a localized error message when `canLaunchUrl` returns false.

### 2.3 Theme notification shown for same theme
**File:** `appearance_page.dart:102-115`
**Fix:** Compare `value != currentCode` before showing the notification.

### 2.4 Raw exception leaked to user in add podcast dialog
**File:** `add_podcast_dialog.dart:53-57`
**Fix:** Show only the localized error message without appending raw `error.toString()`.

### 2.5 Weak URL validation in add podcast dialog
**File:** `add_podcast_dialog.dart:111-113`
**Fix:** Use `Uri.tryParse(value)?.hasAbsolutePath ?? false` for validation, or at minimum check for `http://` or `https://`.

## Category 3: Dead Code / Unused Imports

### 3.1 Three unused imports in episode detail page
**File:** `podcast_episode_detail_page.dart:15,20,21`
**Fix:** Remove `app_colors.dart`, `app_shells.dart`, `custom_adaptive_navigation.dart` imports.

### 3.2 Unused cupertino import in episodes page
**File:** `podcast_episodes_page.dart:1`
**Fix:** Remove `import 'package:flutter/cupertino.dart';`.

### 3.3 Commented-out debug block in episodes page
**File:** `podcast_episodes_page.dart:141-150`
**Fix:** Remove the commented-out block.

### 3.4 Stub _updateHeaderStateForTab method
**File:** `podcast_episode_detail_page.dart:158-160`
**Fix:** Remove the unused `tabIndex` parameter and add a comment that this method intentionally only hides the scroll-to-top button.

## Category 4: i18n

### 4.1 Hardcoded spacing in update dialog
**File:** `update_dialog.dart:323,333,347,367,390,404,432,787,796`
**Fix:** Replace `SizedBox(height: 8)` with `SizedBox(height: context.spacing.sm)` and similar.

### 4.2 Raw exception in download failed message
**File:** `update_dialog.dart:615`
**Fix:** Show only `l10n.update_download_failed` without appending raw exception.

### 4.3 Hardcoded spacing in server config dialog
**File:** `server_config_dialog.dart:290`
**Fix:** Replace `vertical: 10` with appropriate `context.spacing` value.

## Category 5: Mounted Checks / Stale Context

### 5.1 No mounted guard in profile page initState callback
**File:** `profile_page.dart:39-47`
**Fix:** Add `if (!mounted) return;` at the start of the `addPostFrameCallback` callback.

### 5.2 Stale l10n after async gap in change password dialog
**File:** `profile_page.dart:451-496`
**Fix:** Re-read `context.l10n` after the mounted check instead of using the captured value.

### 5.3 Stale l10n after async gap in logout dialog
**File:** `profile_page.dart:639-664`
**Fix:** Same — re-read `context.l10n` after the mounted check.
