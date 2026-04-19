# Profile Sub-Pages Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 20 issues across profile sub-pages covering crashes, i18n, UX, dead code, performance, and code duplication.

**Architecture:** Fix issues file-by-file in priority order (crashes first, then i18n, then UX, then cleanup). Each task produces a self-contained commit.

**Tech Stack:** Flutter 3.8+, Dart, Riverpod, GoRouter, flutter_localizations (ARB files)

---

## Files Modified

| File | Issues |
|------|--------|
| `frontend/lib/features/profile/presentation/pages/profile_page.dart` | 1.1, 4.1, 4.2, 5.3 |
| `frontend/lib/features/profile/presentation/pages/profile_history_page.dart` | 1.3, 3.1, 3.2 |
| `frontend/lib/features/profile/presentation/pages/profile_subscriptions_page.dart` | 3.4, 4.5 |
| `frontend/lib/features/profile/presentation/pages/profile_cache_management_page.dart` | 2.2, 3.5, 6.1 |
| `frontend/lib/features/profile/presentation/widgets/profile_activity_cards.dart` | 4.3, 7.1 |
| `frontend/lib/features/profile/presentation/providers/profile_ui_providers.dart` | 3.3, 4.4 |
| `frontend/lib/features/podcast/presentation/providers/base/cached_async_notifier.dart` | 1.2 |
| `frontend/lib/core/router/app_router.dart` | 5.1-5.2 |
| `frontend/lib/features/profile/presentation/pages/privacy_page.dart` | 5.1 (double-scrollable) |
| `frontend/lib/features/profile/presentation/pages/terms_page.dart` | 5.2 (double-scrollable) |
| `frontend/lib/core/localization/app_localizations_en.arb` | new i18n keys |
| `frontend/lib/core/localization/app_localizations_zh.arb` | new i18n keys |

---

## Task 1: Fix crash -- empty displayName RangeError (Spec 1.1)

**Files:**
- `frontend/lib/features/profile/presentation/pages/profile_page.dart`

Current code at line 847:
```dart
(user?.displayName ?? l10n.profile_guest_user).characters.first.toUpperCase(),
```

When `displayName` is an empty string, `.characters.first` throws a `RangeError`.

- [ ] In `frontend/lib/features/profile/presentation/pages/profile_page.dart`, replace line 847:

  **Old:**
  ```dart
        (user?.displayName ?? l10n.profile_guest_user).characters.first.toUpperCase(),
  ```

  **New:**
  ```dart
        (user?.displayName ?? l10n.profile_guest_user).characters.firstOrNull?.toUpperCase() ?? '?',
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_page.dart`
- [ ] Commit: `fix(profile): prevent RangeError on empty displayName`

---

## Task 2: Wire up CachedAsyncNotifier.markDisposed (Spec 1.2)

**Files:**
- `frontend/lib/features/podcast/presentation/providers/base/cached_async_notifier.dart`

The `markDisposed()` method at line 123 is never called, meaning `_isDisposed` is never set to `true`, so state updates can leak after widget disposal.

- [ ] In `frontend/lib/features/podcast/presentation/providers/base/cached_async_notifier.dart`, add a new field after line 41 (`bool _isDisposed = false;`):

  **Old (line 41):**
  ```dart
  bool _isDisposed = false;
  ```

  **New:**
  ```dart
  bool _isDisposed = false;
  bool _onDisposeWired = false;
  ```

- [ ] In the same file, add a guarded `ref.onDispose` call at the start of the `runWithCache` method. Insert between line 62 (opening `{`) and line 63 (`final previousData = state.value;`):

  **Old (lines 62-63):**
  ```dart
  }) async {
      final previousData = state.value;
  ```

  **New:**
  ```dart
  }) async {
      if (!_onDisposeWired) {
        _onDisposeWired = true;
        ref.onDispose(markDisposed);
      }
      final previousData = state.value;
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/podcast/presentation/providers/base/cached_async_notifier.dart`
- [ ] Commit: `fix(podcast): wire up CachedAsyncNotifier disposal guard`

---

## Task 3: Fix double data fetch in ProfileHistoryPage (Spec 1.3)

**Files:**
- `frontend/lib/features/profile/presentation/pages/profile_history_page.dart`

The `playbackHistoryLiteProvider`'s `build()` method already calls `load()` on initialization. The explicit `initState` call at lines 28-38 causes a redundant second fetch.

- [ ] In `frontend/lib/features/profile/presentation/pages/profile_history_page.dart`, delete the entire `initState` override (lines 28-38):

  **Delete:**
  ```dart
    @override
    void initState() {
      super.initState();
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) {
          return;
        }
        ref.read(playbackHistoryLiteProvider.notifier).load();
      });
    }
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_history_page.dart`
- [ ] Commit: `fix(profile): remove redundant history data fetch in initState`

---

## Task 4: Fix i18n in ProfileHistoryPage (Spec 3.1, 3.2)

**Files:**
- `frontend/lib/features/profile/presentation/pages/profile_history_page.dart`

The ARB files already define `profile_history_subtitle` and `profile_history_episode_count` but they are not used. The page has 4 hardcoded English strings.

- [ ] Replace the first hardcoded subtitle (line 77, empty-state branch):

  **Old:**
  ```dart
                            subtitle:
                                'Resume episodes and review recently played content.',
  ```

  **New:**
  ```dart
                            subtitle: l10n.profile_history_subtitle,
  ```

- [ ] Replace the episode count string (line 130):

  **Old:**
  ```dart
                              subtitle:
                                  '${episodes.length} recently played episodes',
  ```

  **New:**
  ```dart
                              subtitle:
                                  l10n.profile_history_episode_count(episodes.length),
  ```

- [ ] Replace the second hardcoded subtitle (line 163, loading branch):

  **Old:**
  ```dart
                      subtitle:
                          'Resume episodes and review recently played content.',
  ```

  **New:**
  ```dart
                      subtitle: l10n.profile_history_subtitle,
  ```

- [ ] Replace the third hardcoded subtitle (line 177, error branch):

  **Old:**
  ```dart
                      subtitle:
                          'Resume episodes and review recently played content.',
  ```

  **New:**
  ```dart
                      subtitle: l10n.profile_history_subtitle,
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_history_page.dart`
- [ ] Commit: `fix(i18n): use localized strings in ProfileHistoryPage`

---

## Task 5: Fix hardcoded strings in profile_ui_providers (Spec 3.3) and notification flash (Spec 4.4)

**Files:**
- `frontend/lib/features/profile/presentation/providers/profile_ui_providers.dart`

Three issues: (1) `'Loading...'` is an English string in a non-i18n context, (2) `'Unknown'` same, (3) `NotificationPreferenceNotifier` defaults to `true`, causing a visual flash from "on" to "off" when the real preference loads.

- [ ] In `AppVersionNotifier.build()`, change the default return (line 51):

  **Old:**
  ```dart
      return 'Loading...';
  ```

  **New:**
  ```dart
      return '';
  ```

- [ ] In `AppVersionNotifier._loadVersion()`, change the error fallback (line 60):

  **Old:**
  ```dart
        state = 'Unknown';
  ```

  **New:**
  ```dart
        state = '\u2014';
  ```

- [ ] In `NotificationPreferenceNotifier.build()`, change the default return (line 13):

  **Old:**
  ```dart
      return true;
  ```

  **New:**
  ```dart
      return false;
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/providers/profile_ui_providers.dart`
- [ ] Commit: `fix(profile): remove hardcoded English strings and fix notification switch flash`

---

## Task 6: Fix hardcoded subscription count format (Spec 3.4)

**Files:**
- `frontend/lib/features/profile/presentation/pages/profile_subscriptions_page.dart`
- `frontend/lib/core/localization/app_localizations_en.arb`
- `frontend/lib/core/localization/app_localizations_zh.arb`

The end-of-list indicator at line 447 uses `'${l10n.profile_subscriptions}: $total'` which is not properly localized.

- [ ] In `frontend/lib/core/localization/app_localizations_en.arb`, add a new key after line 2278 (after the `@profile_subscriptions_count` closing brace):

  **Insert after line 2278:**
  ```json
      "profile_subscriptions_all_loaded":  "All {count} subscriptions loaded",
      "@profile_subscriptions_all_loaded":  {
                                               "description":  "Message shown when all subscriptions have been loaded",
                                               "placeholders":  {
                                                                    "count":  {
                                                                                  "type":  "int"
                                                                              }
                                                                }
                                           },
  ```

- [ ] In `frontend/lib/core/localization/app_localizations_zh.arb`, add the matching key after line 2232 (after the `@profile_subscriptions_count` closing brace):

  **Insert after line 2232:**
  ```json
      "profile_subscriptions_all_loaded":  "已加载全部 {count} 个订阅",
      "@profile_subscriptions_all_loaded":  {
                                               "description":  "所有订阅已加载完成时显示的消息",
                                               "placeholders":  {
                                                                    "count":  {
                                                                                  "type":  "int"
                                                                              }
                                                                }
                                           },
  ```

- [ ] Run: `cd frontend && flutter gen-l10n`

- [ ] In `frontend/lib/features/profile/presentation/pages/profile_subscriptions_page.dart`, replace line 447:

  **Old:**
  ```dart
            '${l10n.profile_subscriptions}: $total',
  ```

  **New:**
  ```dart
            l10n.profile_subscriptions_all_loaded(total),
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_subscriptions_page.dart`
- [ ] Commit: `fix(i18n): localize subscriptions end-of-list indicator`

---

## Task 7: Fix cache management -- make _objectBytes sync (Spec 6.1), remove hardcoded MB extraction (Spec 3.5), fix _clearAll dialog (Spec 2.2)

**Files:**
- `frontend/lib/features/profile/presentation/pages/profile_cache_management_page.dart`

### 7a. Make `_objectBytes` synchronous (Spec 6.1)

The method does no I/O -- it just reads a property. Making it `async` forces unnecessary `await` at the call site.

- [ ] Replace lines 149-153:

  **Old:**
  ```dart
    Future<int> _objectBytes(CacheObject object) async {
      final length = object.length;
      if (length != null && length >= 0) return length;
      return 0;
    }
  ```

  **New:**
  ```dart
    int _objectBytes(CacheObject object) {
      final length = object.length;
      if (length != null && length >= 0) return length;
      return 0;
    }
  ```

- [ ] Update the call site at line 173 (inside `_loadStats`):

  **Old:**
  ```dart
        final bytes = await _objectBytes(obj);
  ```

  **New:**
  ```dart
        final bytes = _objectBytes(obj);
  ```

### 7b. Remove hardcoded MB string extraction (Spec 3.5)

Line 466 does `_formatMB(stats.totalBytes).replaceAll(' MB', '')` which is fragile.

- [ ] Replace line 466:

  **Old:**
  ```dart
                  _formatMB(stats.totalBytes).replaceAll(' MB', ''),
  ```

  **New:**
  ```dart
                  (stats.totalBytes / (1024 * 1024)).toStringAsFixed(2),
  ```

### 7c. Fix `_clearAll()` dialog stuck issue (Spec 2.2)

If the widget is unmounted during the async clear operation, `Navigator.of(context)` will fail and the loading dialog stays stuck. Fix by capturing `NavigatorState` before the async gap.

- [ ] In the `_clearAll()` method, capture the navigator before the dialog is shown. After line 292 (`if (confirm != true || !mounted) return;`), add:

  **Old (lines 292-294):**
  ```dart
      if (confirm != true || !mounted) return;

      showAppDialog<void>(
  ```

  **New:**
  ```dart
      if (confirm != true || !mounted) return;

      final nav = Navigator.of(context);

      showAppDialog<void>(
  ```

- [ ] Replace the two `Navigator.of(context).pop()` calls (lines 331 and 336) with `nav.pop()`:

  **Line 331 -- Old:**
  ```dart
        Navigator.of(context).pop();
  ```

  **Line 331 -- New:**
  ```dart
        nav.pop();
  ```

  **Line 336 -- Old:**
  ```dart
        Navigator.of(context).pop();
  ```

  **Line 336 -- New:**
  ```dart
        nav.pop();
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_cache_management_page.dart`
- [ ] Commit: `fix(profile): improve cache management page robustness and performance`

---

## Task 8: Simplify change-password dialog (Spec 4.1), simplify edit-profile dialog (Spec 4.2), remove dead code (Spec 5.3)

**Files:**
- `frontend/lib/features/profile/presentation/pages/profile_page.dart`
- `frontend/lib/core/localization/app_localizations_en.arb`
- `frontend/lib/core/localization/app_localizations_zh.arb`

### 8a. Add new ARB key for password reset email description

- [ ] In `frontend/lib/core/localization/app_localizations_en.arb`, add after line 2737 (after `@profile_send_reset_link` closing brace):

  **Insert after line 2737:**
  ```json
      "profile_password_reset_email_description":  "A password reset link will be sent to {email}. Check your inbox after clicking Send.",
      "@profile_password_reset_email_description":  {
                                                        "description":  "Description text in the change password dialog explaining the reset email",
                                                        "placeholders":  {
                                                                             "email":  {
                                                                                           "type":  "String"
                                                                                       }
                                                                         }
                                                    },
  ```

- [ ] In `frontend/lib/core/localization/app_localizations_zh.arb`, add after line 2691 (after `@profile_send_reset_link` closing brace):

  **Insert after line 2691:**
  ```json
      "profile_password_reset_email_description":  "密码重置链接将发送到 {email}，点击发送后请检查您的收件箱。",
      "@profile_password_reset_email_description":  {
                                                        "description":  "修改密码对话框中的描述文本，说明重置邮件的发送",
                                                        "placeholders":  {
                                                                             "email":  {
                                                                                           "type":  "String"
                                                                                       }
                                                                         }
                                                    },
  ```

- [ ] Run: `cd frontend && flutter gen-l10n`

### 8b. Replace `_showChangePasswordDialog` with simplified version (Spec 4.1)

The current implementation (lines 494-665) creates 3 `TextEditingController`s that are never disposed and a form that ultimately just calls `forgotPassword` anyway. Replace with a simple confirmation dialog.

- [ ] Replace lines 494-665 (the entire `_showChangePasswordDialog` method) with:

  **Old (lines 494-665):**
  ```dart
    void _showChangePasswordDialog(BuildContext context) {
      final l10n = context.l10n;
      final currentPasswordController = TextEditingController();
      ...
    }
  ```

  **New:**
  ```dart
    void _showChangePasswordDialog(BuildContext context) {
      final l10n = context.l10n;
      final authState = ref.read(authProvider);
      final userEmail = authState.user?.email;

      _showConstrainedDialog<void>(
        context,
        builder: (dialogContext) {
          return AlertDialog.adaptive(
            backgroundColor: Colors.transparent,
            insetPadding: ResponsiveDialogHelper.insetPadding(),
            title: Text(l10n.profile_password_change_title),
            content: Text(
              userEmail != null
                  ? l10n.profile_password_reset_email_description(userEmail)
                  : l10n.profile_password_change_failed,
            ),
            actions: [
              AdaptiveButton(
                style: AdaptiveButtonStyle.text,
                onPressed: () => Navigator.of(dialogContext).pop(),
                child: Text(l10n.cancel),
              ),
              if (userEmail != null)
                AdaptiveButton(
                  style: AdaptiveButtonStyle.filled,
                  onPressed: () async {
                    Navigator.of(dialogContext).pop();
                    try {
                      await ref
                          .read(authProvider.notifier)
                          .forgotPassword(userEmail);
                      if (context.mounted) {
                        showTopFloatingNotice(
                          context,
                          message: l10n.profile_password_reset_email_sent,
                        );
                      }
                    } catch (e) {
                      if (context.mounted) {
                        showTopFloatingNotice(
                          context,
                          message: l10n.profile_password_change_failed,
                        );
                      }
                    }
                  },
                  child: Text(l10n.profile_send_reset_link),
                ),
            ],
          );
        },
      );
    }
  ```

### 8c. Replace `_showEditProfileDialog` with simple notice (Spec 4.2)

The current dialog (lines 351-423) creates 2 `TextEditingController`s that are never disposed and shows disabled fields. Replace with a simple notice.

- [ ] Replace lines 351-423 (the entire `_showEditProfileDialog` method) with:

  **Old (lines 351-423):**
  ```dart
    void _showEditProfileDialog(BuildContext context) {
      final l10n = context.l10n;
      final authState = ref.read(authProvider);
      final user = authState.user;
      ...
    }
  ```

  **New:**
  ```dart
    void _showEditProfileDialog(BuildContext context) {
      final l10n = context.l10n;
      _showConstrainedDialog<void>(
        context,
        builder: (dialogContext) {
          return AlertDialog.adaptive(
            backgroundColor: Colors.transparent,
            insetPadding: ResponsiveDialogHelper.insetPadding(),
            title: Text(l10n.profile_edit_profile),
            content: Text(l10n.profile_edit_coming_soon_subtitle),
            actions: [
              AdaptiveButton(
                style: AdaptiveButtonStyle.text,
                onPressed: () => Navigator.of(dialogContext).pop(),
                child: Text(l10n.ok),
              ),
            ],
          );
        },
      );
    }
  ```

### 8d. Remove dead code -- unused `_buildCard` method (Spec 5.3)

- [ ] Delete lines 301-303:

  **Old:**
  ```dart
    // ignore: unused_element
    Widget _buildCard(Widget child) =>
        Card(margin: EdgeInsets.zero, child: child);
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/pages/profile_page.dart`
- [ ] Commit: `fix(profile): simplify change-password and edit-profile dialogs, remove dead code`

---

## Task 9: Fix activity cards -- tappable differentiation (Spec 4.3) and code duplication (Spec 7.1)

**Files:**
- `frontend/lib/features/profile/presentation/widgets/profile_activity_cards.dart`

### 9a. Extract shared `_buildCardList` to eliminate duplication (Spec 7.1)

Lines 59-123 (mobile Column) and lines 132-188 (desktop Wrap) contain identical card definitions. Extract into a shared method.

- [ ] Add the following method to `ProfileActivityCards` (insert before the existing `_buildActivityCard` method at line 201):

  ```dart
    List<Widget> _buildCardList(
      BuildContext context, {
      required String subscriptionCount,
      required String episodeCount,
      required String summaryCount,
      required String historyCount,
      required String latestDailyReportDateText,
      required String highlightsCount,
      required ColorScheme scheme,
    }) {
      final l10n = context.l10n;
      return [
        _buildActivityCard(
          context,
          icon: Icons.subscriptions_outlined,
          label: l10n.profile_subscriptions,
          value: subscriptionCount,
          color: scheme.secondary,
          onTap: () => context.push('/profile/subscriptions'),
          showChevron: true,
          cardKey: const Key('profile_subscriptions_card'),
        ),
        _buildActivityCard(
          context,
          icon: Icons.podcasts,
          label: l10n.podcast_episodes,
          value: episodeCount,
          color: scheme.secondary,
        ),
        _buildActivityCard(
          context,
          icon: Icons.auto_awesome,
          label: l10n.profile_ai_summary,
          value: summaryCount,
          color: scheme.secondary,
        ),
        _buildActivityCard(
          context,
          icon: Icons.history,
          label: l10n.profile_viewed_title,
          value: historyCount,
          color: scheme.secondary,
          onTap: () => context.push('/profile/history'),
          showChevron: true,
          chevronKey: const Key('profile_viewed_card_chevron'),
        ),
        _buildActivityCard(
          context,
          icon: Icons.summarize_outlined,
          label: l10n.podcast_daily_report_title,
          value: latestDailyReportDateText,
          color: scheme.secondary,
          onTap: () =>
              PodcastNavigation.goToDailyReport(context, source: 'profile'),
          showChevron: true,
          cardKey: const Key('profile_daily_report_card'),
        ),
        _buildActivityCard(
          context,
          icon: Icons.lightbulb_outline,
          label: l10n.podcast_highlights_title,
          value: highlightsCount,
          color: scheme.secondary,
          onTap: () => PodcastNavigation.goToHighlights(context, source: 'profile'),
          showChevron: true,
          cardKey: const Key('profile_highlights_card'),
        ),
      ];
    }
  ```

### 9b. Replace mobile Column with shared list (lines 59-123)

- [ ] Replace lines 59-123:

  **Old:**
  ```dart
        if (isMobile) {
          return Column(
            children: [
              _buildActivityCard(
                context,
                icon: Icons.subscriptions_outlined,
                label: l10n.profile_subscriptions,
                value: subscriptionCount,
                color: scheme.secondary,
                onTap: () => context.push('/profile/subscriptions'),
                showChevron: true,
                cardKey: const Key('profile_subscriptions_card'),
              ),
              SizedBox(height: context.spacing.smMd),
              _buildActivityCard(
                context,
                icon: Icons.podcasts,
                label: l10n.podcast_episodes,
                value: episodeCount,
                color: scheme.secondary,
              ),
              SizedBox(height: context.spacing.smMd),
              _buildActivityCard(
                context,
                icon: Icons.auto_awesome,
                label: l10n.profile_ai_summary,
                value: summaryCount,
                color: scheme.secondary,
              ),
              SizedBox(height: context.spacing.smMd),
              _buildActivityCard(
                context,
                icon: Icons.history,
                label: l10n.profile_viewed_title,
                value: historyCount,
                color: scheme.secondary,
                onTap: () => context.push('/profile/history'),
                showChevron: true,
                chevronKey: const Key('profile_viewed_card_chevron'),
              ),
              SizedBox(height: context.spacing.smMd),
              _buildActivityCard(
                context,
                icon: Icons.summarize_outlined,
                label: l10n.podcast_daily_report_title,
                value: latestDailyReportDateText,
                color: scheme.secondary,
                onTap: () =>
                    PodcastNavigation.goToDailyReport(context, source: 'profile'),
                showChevron: true,
                cardKey: const Key('profile_daily_report_card'),
              ),
              SizedBox(height: context.spacing.md),
              _buildActivityCard(
                context,
                icon: Icons.lightbulb_outline,
                label: l10n.podcast_highlights_title,
                value: highlightsCount,
                color: scheme.secondary,
                onTap: () => PodcastNavigation.goToHighlights(context, source: 'profile'),
                showChevron: true,
                cardKey: const Key('profile_highlights_card'),
              ),
            ],
          );
        }
  ```

  **New:**
  ```dart
        if (isMobile) {
          final cards = _buildCardList(
            context,
            subscriptionCount: subscriptionCount,
            episodeCount: episodeCount,
            summaryCount: summaryCount,
            historyCount: historyCount,
            latestDailyReportDateText: latestDailyReportDateText,
            highlightsCount: highlightsCount,
            scheme: scheme,
          );
          return Column(
            children: cards
                .expand<Widget>(
                  (card) => [card, SizedBox(height: context.spacing.smMd)],
                )
                .toList()
              ..removeLast(),
          );
        }
  ```

### 9c. Replace desktop LayoutBuilder's inline card list with shared list (lines 132-188)

- [ ] Replace lines 132-188 (the `final cards = <Widget>[` block):

  **Old:**
  ```dart
        final cards = <Widget>[
          _buildActivityCard(
            context,
            icon: Icons.subscriptions_outlined,
            label: l10n.profile_subscriptions,
            value: subscriptionCount,
            color: scheme.secondary,
            onTap: () => context.push('/profile/subscriptions'),
            showChevron: true,
            cardKey: const Key('profile_subscriptions_card'),
          ),
          _buildActivityCard(
            context,
            icon: Icons.podcasts,
            label: l10n.podcast_episodes,
            value: episodeCount,
            color: scheme.secondary,
          ),
          _buildActivityCard(
            context,
            icon: Icons.auto_awesome,
            label: l10n.profile_ai_summary,
            value: summaryCount,
            color: scheme.secondary,
          ),
          _buildActivityCard(
            context,
            icon: Icons.history,
            label: l10n.profile_viewed_title,
            value: historyCount,
            color: scheme.secondary,
            onTap: () => context.push('/profile/history'),
            showChevron: true,
            chevronKey: const Key('profile_viewed_card_chevron'),
          ),
          _buildActivityCard(
            context,
            icon: Icons.summarize_outlined,
            label: l10n.podcast_daily_report_title,
            value: latestDailyReportDateText,
            color: scheme.secondary,
            onTap: () =>
                PodcastNavigation.goToDailyReport(context, source: 'profile'),
            showChevron: true,
            cardKey: const Key('profile_daily_report_card'),
          ),
          _buildActivityCard(
            context,
            icon: Icons.lightbulb_outline,
            label: l10n.podcast_highlights_title,
            value: highlightsCount,
            color: scheme.secondary,
            onTap: () => PodcastNavigation.goToHighlights(context, source: 'profile'),
            showChevron: true,
            cardKey: const Key('profile_highlights_card'),
          ),
        ];
  ```

  **New:**
  ```dart
        final cards = _buildCardList(
          context,
          subscriptionCount: subscriptionCount,
          episodeCount: episodeCount,
          summaryCount: summaryCount,
          historyCount: historyCount,
          latestDailyReportDateText: latestDailyReportDateText,
          highlightsCount: highlightsCount,
          scheme: scheme,
        );
  ```

### 9d. Differentiate tappable vs non-tappable cards (Spec 4.3)

Cards without `onTap` still wrap in `InkWell`, giving a false affordance.

- [ ] Add a helper method to `ProfileActivityCards` (insert after `_cardMargin`):

  ```dart
    Widget _wrapIfTapable({
      required VoidCallback? onTap,
      required double borderRadius,
      required Widget child,
    }) {
      if (onTap == null) return child;
      return InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(borderRadius),
        child: child,
      );
    }
  ```

- [ ] In `_buildActivityCard`, replace the `InkWell` wrapping (lines 218-220):

  **Old:**
  ```dart
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(extension.cardRadius),
          child: SurfacePanel(
  ```

  And replace the corresponding closing parenthesis/bracket pattern. The full replacement for the `_buildActivityCard` method body starting from `return Padding(` through the closing `);`:

  **Old (lines 215-267):**
  ```dart
      return Padding(
        key: cardKey,
        padding: _cardMargin(context),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(extension.cardRadius),
          child: SurfacePanel(
            borderRadius: extension.cardRadius,
            showBorder: false,
            child: Row(
              children: [
                Container(
                  width: context.spacing.xl,
                  height: context.spacing.xl,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.1),
                    borderRadius: AppRadius.mdRadius,
                  ),
                  child: Icon(icon, color: color, size: 20),
                ),
                SizedBox(width: context.spacing.md),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        label,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: scheme.onSurfaceVariant,
                        ),
                      ),
                      SizedBox(height: context.spacing.sm),
                      Text(
                        value,
                        style: theme.textTheme.headlineSmall
                            ?.copyWith(fontWeight: FontWeight.w700),
                      ),
                    ],
                  ),
                ),
                if (showChevron)
                  Icon(
                    Icons.chevron_right,
                    key: chevronKey,
                    color: scheme.onSurfaceVariant,
                    size: 22,
                  ),
              ],
            ),
          ),
        ),
      );
  ```

  **New:**
  ```dart
      return Padding(
        key: cardKey,
        padding: _cardMargin(context),
        child: _wrapIfTapable(
          onTap: onTap,
          borderRadius: extension.cardRadius,
          child: SurfacePanel(
            borderRadius: extension.cardRadius,
            showBorder: false,
            child: Row(
              children: [
                Container(
                  width: context.spacing.xl,
                  height: context.spacing.xl,
                  decoration: BoxDecoration(
                    color: color.withValues(alpha: 0.1),
                    borderRadius: AppRadius.mdRadius,
                  ),
                  child: Icon(icon, color: color, size: 20),
                ),
                SizedBox(width: context.spacing.md),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        label,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: scheme.onSurfaceVariant,
                        ),
                      ),
                      SizedBox(height: context.spacing.sm),
                      Text(
                        value,
                        style: theme.textTheme.headlineSmall
                            ?.copyWith(fontWeight: FontWeight.w700),
                      ),
                    ],
                  ),
                ),
                if (showChevron)
                  Icon(
                    Icons.chevron_right,
                    key: chevronKey,
                    color: scheme.onSurfaceVariant,
                    size: 22,
                  ),
              ],
            ),
          ),
        ),
      );
  ```

- [ ] Run: `cd frontend && flutter analyze lib/features/profile/presentation/widgets/profile_activity_cards.dart`
- [ ] Commit: `refactor(profile): deduplicate activity cards and differentiate tappable state`

---

## Task 10: Register orphaned PrivacyPage and TermsPage routes (Spec 5.1, 5.2)

**Files:**
- `frontend/lib/core/router/app_router.dart`
- `frontend/lib/features/profile/presentation/pages/privacy_page.dart`
- `frontend/lib/features/profile/presentation/pages/terms_page.dart`
- `frontend/lib/features/profile/presentation/pages/profile_page.dart`

The `PrivacyPage` and `TermsPage` exist in the codebase but have no routes registered. They also have a double-scrollable issue (`SliverFillRemaining` + `SingleChildScrollView` inside a `CustomScrollView`). The profile page has no navigation items to reach them.

Note: The ARB keys `profile_privacy_policy`, `profile_privacy_policy_subtitle`, `profile_terms_of_service`, `profile_terms_subtitle` already exist in both ARB files. No new ARB keys needed.

### 10a. Fix double-scrollable in PrivacyPage

- [ ] In `frontend/lib/features/profile/presentation/pages/privacy_page.dart`, replace lines 32-105 (the `SliverFillRemaining` containing `SingleChildScrollView`):

  **Old (lines 32-105):**
  ```dart
                SliverFillRemaining(
                  hasScrollBody: false,
                  child: SingleChildScrollView(
                    padding: EdgeInsets.symmetric(
                      horizontal: context.spacing.mdLg,
                      vertical: context.spacing.sm,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          l10n.privacy_policy_title,
                          style: theme.textTheme.headlineSmall?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        SizedBox(height: context.spacing.sm),
                        Text(
                          l10n.privacy_policy_last_updated,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                        SizedBox(height: context.spacing.lg),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_intro,
                          body: l10n.privacy_section_intro_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_collection,
                          body: l10n.privacy_section_collection_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_usage,
                          body: l10n.privacy_section_usage_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_storage,
                          body: l10n.privacy_section_storage_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_sharing,
                          body: l10n.privacy_section_sharing_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_rights,
                          body: l10n.privacy_section_rights_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_children,
                          body: l10n.privacy_section_children_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_changes,
                          body: l10n.privacy_section_changes_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_contact,
                          body: l10n.privacy_section_contact_body,
                        ),
                        SizedBox(height: context.spacing.xl),
                      ],
                    ),
                  ),
                ),
  ```

  **New:**
  ```dart
                SliverToBoxAdapter(
                  child: Padding(
                    padding: EdgeInsets.symmetric(
                      horizontal: context.spacing.mdLg,
                      vertical: context.spacing.sm,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          l10n.privacy_policy_title,
                          style: theme.textTheme.headlineSmall?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        SizedBox(height: context.spacing.sm),
                        Text(
                          l10n.privacy_policy_last_updated,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                        SizedBox(height: context.spacing.lg),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_intro,
                          body: l10n.privacy_section_intro_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_collection,
                          body: l10n.privacy_section_collection_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_usage,
                          body: l10n.privacy_section_usage_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_storage,
                          body: l10n.privacy_section_storage_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_sharing,
                          body: l10n.privacy_section_sharing_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_rights,
                          body: l10n.privacy_section_rights_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_children,
                          body: l10n.privacy_section_children_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_changes,
                          body: l10n.privacy_section_changes_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.privacy_section_contact,
                          body: l10n.privacy_section_contact_body,
                        ),
                        SizedBox(height: context.spacing.xl),
                      ],
                    ),
                  ),
                ),
  ```

### 10b. Fix double-scrollable in TermsPage

- [ ] In `frontend/lib/features/profile/presentation/pages/terms_page.dart`, replace lines 32-96 (the `SliverFillRemaining` containing `SingleChildScrollView`):

  **Old (lines 32-96):**
  ```dart
                SliverFillRemaining(
                  hasScrollBody: false,
                  child: SingleChildScrollView(
                    padding: EdgeInsets.symmetric(
                      horizontal: context.spacing.mdLg,
                      vertical: context.spacing.sm,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          l10n.terms_of_service_title,
                          style: theme.textTheme.headlineSmall?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        SizedBox(height: context.spacing.sm),
                        Text(
                          l10n.terms_of_service_last_updated,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                        SizedBox(height: context.spacing.lg),
                        _buildSection(
                          context,
                          title: l10n.terms_section_acceptance,
                          body: l10n.terms_section_acceptance_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_use,
                          body: l10n.terms_section_use_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_ip,
                          body: l10n.terms_section_ip_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_liability,
                          body: l10n.terms_section_liability_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_changes,
                          body: l10n.terms_section_changes_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_governing_law,
                          body: l10n.terms_section_governing_law_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_contact,
                          body: l10n.terms_section_contact_body,
                        ),
                        SizedBox(height: context.spacing.xl),
                      ],
                    ),
                  ),
                ),
  ```

  **New:**
  ```dart
                SliverToBoxAdapter(
                  child: Padding(
                    padding: EdgeInsets.symmetric(
                      horizontal: context.spacing.mdLg,
                      vertical: context.spacing.sm,
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          l10n.terms_of_service_title,
                          style: theme.textTheme.headlineSmall?.copyWith(
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        SizedBox(height: context.spacing.sm),
                        Text(
                          l10n.terms_of_service_last_updated,
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                        SizedBox(height: context.spacing.lg),
                        _buildSection(
                          context,
                          title: l10n.terms_section_acceptance,
                          body: l10n.terms_section_acceptance_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_use,
                          body: l10n.terms_section_use_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_ip,
                          body: l10n.terms_section_ip_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_liability,
                          body: l10n.terms_section_liability_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_changes,
                          body: l10n.terms_section_changes_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_governing_law,
                          body: l10n.terms_section_governing_law_body,
                        ),
                        _buildSection(
                          context,
                          title: l10n.terms_section_contact,
                          body: l10n.terms_section_contact_body,
                        ),
                        SizedBox(height: context.spacing.xl),
                      ],
                    ),
                  ),
                ),
  ```

### 10c. Add routes and imports in app_router.dart

- [ ] In `frontend/lib/core/router/app_router.dart`, add two imports after line 30 (after the `profile_subscriptions_page.dart` import):

  **Insert after line 30:**
  ```dart
  import 'package:personal_ai_assistant/features/profile/presentation/pages/privacy_page.dart';
  import 'package:personal_ai_assistant/features/profile/presentation/pages/terms_page.dart';
  ```

- [ ] Add two routes inside the profile sub-routes (after the `downloads` route at line 223, before the closing `]` at line 224):

  **Insert after line 223 (after the downloads route's closing `),`):**
  ```dart
                    GoRoute(
                      path: 'privacy',
                      name: 'profile-privacy',
                      parentNavigatorKey: appNavigatorKey,
                      pageBuilder: (context, state) => _buildModalPage(
                        state: state,
                        child: const _PlayerAwareRouteFrame(
                          child: PrivacyPage(),
                        ),
                      ),
                    ),
                    GoRoute(
                      path: 'terms',
                      name: 'profile-terms',
                      parentNavigatorKey: appNavigatorKey,
                      pageBuilder: (context, state) => _buildModalPage(
                        state: state,
                        child: const _PlayerAwareRouteFrame(
                          child: TermsPage(),
                        ),
                      ),
                    ),
  ```

### 10d. Add Privacy and Terms items to the About section in profile_page.dart

- [ ] In `frontend/lib/features/profile/presentation/pages/profile_page.dart`, add two new items to the `aboutItems` list (after the version item at line 166, before the closing `];` at line 166):

  The `aboutItems` list is defined at lines 150-166. Add two items after the version `_SettingsItemConfig` (after line 165's closing `),`):

  **Insert after line 165:**
  ```dart
        _SettingsItemConfig(
          icon: Icons.privacy_tip_outlined,
          title: l10n.profile_privacy_policy,
          subtitle: l10n.profile_privacy_policy_subtitle,
          onTap: () => context.push('/profile/privacy'),
        ),
        _SettingsItemConfig(
          icon: Icons.description_outlined,
          title: l10n.profile_terms_of_service,
          subtitle: l10n.profile_terms_subtitle,
          onTap: () => context.push('/profile/terms'),
        ),
  ```

- [ ] Run: `cd frontend && flutter analyze`
- [ ] Commit: `feat(profile): register Privacy and Terms page routes, add navigation entries`

---

## Task 11: Final verification

- [ ] Run full analysis: `cd frontend && flutter analyze`
- [ ] Run tests: `cd frontend && flutter test`
- [ ] Fix any issues found
