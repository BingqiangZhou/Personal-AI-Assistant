# Unified Title Bar Design Spec

## Problem

The app has 5 distinct title/top-bar approaches across pages, causing visual inconsistency and a non-native iOS experience on sub-pages:

| Approach | Pages | iOS Native? |
|----------|-------|-------------|
| CupertinoSliverNavigationBar / HeroHeader via ContentShell/ProfileShell | 4 (Discover, Library, Profile, Appearance) | Yes |
| CompactHeaderPanel (card-embedded title) | 8 (Highlights, Downloads, DailyReport, History, CacheManagement, Subscriptions, Terms, Privacy) | No |
| Fully custom header row | 2 (PodcastEpisodes, EpisodeDetail) | No |
| AuthShell (card with no nav bar) | 4 (Login, Register, ForgotPassword, ResetPassword) | N/A |
| No header | 2 (Splash, Onboarding) | N/A |

Title font sizes range from 18px to 44px with no consistent pattern. Back button behavior varies across pages. Two unused adaptive components (`adaptiveAppBar()` and `AdaptiveSliverAppBar`) exist in the codebase.

## Strategy

**Dual-platform native approach:**

- iOS: `CupertinoSliverNavigationBar` with large title collapsing behavior
- Android: Material `SliverAppBar` with theme-consistent styling
- Auth pages: keep current card layout (independent auth flow, not browse navigation)
- Back buttons: system default behavior on both platforms (remove manual back buttons)

## Component Changes

### Enhanced AdaptiveSliverAppBar

File: `lib/core/widgets/adaptive/adaptive_sliver_app_bar.dart`

**Current parameters:** `title`, `trailing`, `leading`, `largeTitle`, `bottom`, `backgroundColor`, `automaticallyImplyLeading`

**Parameter changes:**
- Remove `trailing` (single Widget) — replaced by `actions` (List<Widget>)
- Add `actions` (`List<Widget>?`) — primary way to pass action buttons
- Add `heroTag` (`String?`) — optional Cupertino transition hero tag

**iOS path (CupertinoSliverNavigationBar):**
- `largeTitle` defaults to `true`
- `actions` wrapped in `Row(mainAxisSize: MainAxisSize.min)` for `trailing` slot
- System provides automatic back button with previous page title

**Android path (SliverAppBar):**
- `actions` passed directly as SliverAppBar.actions
- `scrolledUnderElevation: 0` (matches app theme, no shadow)
- `surfaceTintColor: Colors.transparent`
- `centerTitle: false` (Android default left-aligned)
- System provides automatic back arrow

**Both platforms:** `backgroundColor` transparent or semi-transparent, text style follows platform defaults.

### adaptiveAppBar()

File: `lib/core/platform/adaptive_app_bar.dart`

No changes. Non-sliver version remains available for future use.

### CompactHeaderPanel

Mark as `@Deprecated` in doc comment. Do not delete yet to avoid breaking any undiscovered usages. Will be removed in a follow-up cleanup.

## Page Migration

### Group A: 8 CompactHeaderPanel Pages (Uniform Migration)

Pages: PodcastHighlights, PodcastDownloads, PodcastDailyReport, ProfileHistory, ProfileCacheManagement, ProfileSubscriptions, Terms, Privacy

**Before:**
```
Scaffold > Material > SafeArea > ResponsiveContainer > Column
  CompactHeaderPanel(title, trailing: [actions + back_btn_on_desktop])
  SizedBox(spacing)
  Expanded(body)
```

**After:**
```
Scaffold > Material > ResponsiveContainer > CustomScrollView
  AdaptiveSliverAppBar(title, actions: [actions])  // no manual back button
  SliverToBoxAdapter(SizedBox spacing)
  SliverFillRemaining(hasScrollBody: true, body)
```

**Per-page action changes:**

| Page | Keep (mobile + desktop) | Remove |
|------|------------------------|--------|
| PodcastHighlights | calendar button | desktop back button |
| PodcastDownloads | delete-all button | desktop back button |
| PodcastDailyReport | calendar button | desktop back button |
| ProfileHistory | (none) | desktop back button |
| ProfileCacheManagement | refresh button | desktop back button |
| ProfileSubscriptions | add button | desktop back button |
| Terms | (none) | back button (always shown) |
| Privacy | (none) | back button (always shown) |

**Additional changes per page:**
- Remove `SafeArea` wrapper (both CupertinoSliverNavigationBar and SliverAppBar handle safe area internally)
- Body content (SurfacePanel, ListView, etc.) unchanged, only wrapper changes from `Expanded` to `SliverFillRemaining`
- Terms/Privacy: keep `ResponsiveContainer(maxWidth: 720)`

### Group B: PodcastEpisodesPage

File: `lib/features/podcast/presentation/pages/podcast_episodes_page.dart`

**Current:** `AdaptiveScaffold` with custom inline `Container(height:56) > Row` header containing cover art, title, refresh/filter buttons.

**Changes:**
- Replace inline header row with `AdaptiveSliverAppBar`
- Move filter chips row to `bottom` parameter (PreferredSizeWidget)
- Cover art thumbnail: keep as `leading` widget in AdaptiveSliverAppBar
- Keep `AdaptiveScaffold` as root widget
- Remove manual `IconButton(Icons.adaptive.arrow_back)` (system handles it)

### Group C: PodcastEpisodeDetailPage

File: `lib/features/podcast/presentation/pages/podcast_episode_detail_page.dart`

**Current:** Complex collapsing hero card (SurfacePanel) with artwork, title, metadata, action buttons, plus separate tab bar.

**Changes:**
- Add `AdaptiveSliverAppBar` above the hero card with episode title
- Remove title text and back button from the hero card itself
- Hero card remains as a decorative element below the nav bar
- Tab bar and content area unchanged
- This is a minimal-touch approach to avoid restructuring the complex animation/scroll logic

## Scope Exclusions

- Auth pages (Login, Register, ForgotPassword, ResetPassword) - keep current card layout
- Splash and Onboarding - no title bars
- ContentShell/ProfileShell - already use CupertinoSliverNavigationBar on iOS
- Theme/AppColors changes - use existing theme tokens
- SurfacePanel, HeaderCapsuleActionButton - no changes to these shared components

## Testing

- Widget tests for `AdaptiveSliverAppBar` on both platforms (iOS/Material)
- Verify back button appears automatically on pushed routes for both platforms
- Verify trailing actions render correctly on both platforms
- Verify large title collapsing works on iOS
- Visual regression check on 8 Group A pages for both platforms
