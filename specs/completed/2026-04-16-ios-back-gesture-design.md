# iOS Back Gesture Fix Design

## Problem

All push-navigated pages in the app cannot be dismissed via the iOS swipe-back gesture. The root cause is `adaptivePageTransition()` in `adaptive_page_route.dart` returning `CustomTransitionPage` for every route. `CustomTransitionPage` bypasses Flutter's `CupertinoPageTransitionsBuilder` and does not implement `CupertinoRouteTransitionMixin`, so iOS back gesture is disabled.

## Solution

Replace `CustomTransitionPage` with platform-appropriate page types:

- **iOS**: `CupertinoPage<T>` — provides native iOS swipe-back gesture and transition animation out of the box
- **Android/Desktop**: `MaterialPage<T>` — works with the theme's `ZoomPageTransitionsBuilder`

## Changes

### File: `frontend/lib/core/platform/adaptive_page_route.dart`

Remove `CustomTransitionPage` and the manual `transitionsBuilder`. Return `CupertinoPage` on iOS and `MaterialPage` on all other platforms. Both accept `fullscreenDialog` and maintain a `key` for GoRouter page identity.

```dart
Page<T> adaptivePageTransition<T>({
  required Widget child,
  required ValueKey<String> pageKey,
  bool fullscreenDialog = false,
}) {
  // Runtime platform detection happens at call sites where BuildContext is
  // available. Here we default to CupertinoPage; callers that have context
  // can check Theme.of(context).platform and call the appropriate factory.
  // Simpler: detect defaultTargetPlatform at the top level.
  if (defaultTargetPlatform == TargetPlatform.iOS) {
    return CupertinoPage<T>(
      key: pageKey,
      child: child,
      fullscreenDialog: fullscreenDialog,
    );
  }
  return MaterialPage<T>(
    key: pageKey,
    child: child,
    fullscreenDialog: fullscreenDialog,
  );
}
```

### No other files need changes

All callers (`app_router.dart` via `_buildPageWithTransition` and `_buildModalPage`) already call `adaptivePageTransition()` and pass the same parameters. The return type changes from `CustomTransitionPage<T>` to `Page<T>`, which is compatible with GoRouter's `GoRoute.pageBuilder`.

## Verification

1. On iOS: swipe from left edge on any pushed page (podcast detail, episode list, settings) should pop back
2. On Android: no regression, pages still transition with zoom/fade as before
3. `fullscreenDialog: true` pages (profile sub-routes) should still show the close button and slide up from bottom
