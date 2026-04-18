import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/platform/platform_helper.dart';

/// Adaptive scaffold: CupertinoPageScaffold on iOS, Scaffold on Android.
class AdaptiveScaffold extends StatelessWidget {
  const AdaptiveScaffold({
    super.key,
    this.navigationBar,
    this.child,
    this.backgroundColor,
    this.resizeToAvoidBottomInset,
    this.bottomNavigationBar,
    this.floatingActionButton,
  });

  /// Navigation bar. On iOS, expects a [CupertinoNavigationBar].
  /// On other platforms, expects an [AppBar] (PreferredSizeWidget).
  final Widget? navigationBar;

  /// Page body content.
  final Widget? child;

  /// Background color. Defaults to system background on both platforms.
  final Color? backgroundColor;

  /// Whether to resize when the keyboard appears.
  final bool? resizeToAvoidBottomInset;

  /// Bottom navigation bar. Ignored on iOS CupertinoPageScaffold.
  final Widget? bottomNavigationBar;

  /// Floating action button. Ignored on iOS CupertinoPageScaffold.
  final Widget? floatingActionButton;

  @override
  Widget build(BuildContext context) {
    if (PlatformHelper.isIOS(context)) {
      final cupertinoNav = navigationBar is CupertinoNavigationBar
          ? navigationBar as CupertinoNavigationBar?
          : null;
      return CupertinoPageScaffold(
        navigationBar: cupertinoNav,
        child: child ?? const SizedBox.shrink(),
        backgroundColor: backgroundColor,
        resizeToAvoidBottomInset: resizeToAvoidBottomInset ?? true,
      );
    }

    final appBar = navigationBar is PreferredSizeWidget
        ? navigationBar as PreferredSizeWidget?
        : null;
    return Scaffold(
      appBar: appBar,
      body: child,
      backgroundColor: backgroundColor,
      resizeToAvoidBottomInset: resizeToAvoidBottomInset ?? true,
      bottomNavigationBar: bottomNavigationBar,
      floatingActionButton: floatingActionButton,
    );
  }
}
