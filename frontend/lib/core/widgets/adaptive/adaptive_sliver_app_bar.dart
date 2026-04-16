import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/platform/platform_helper.dart';

/// Adaptive sliver app bar with large title collapsing.
///
/// iOS: [CupertinoSliverNavigationBar] with large title → collapsed title.
/// Android: Material [SliverAppBar] with flexible space.
class AdaptiveSliverAppBar extends StatelessWidget {
  const AdaptiveSliverAppBar({
    required this.title,
    super.key,
    this.trailing,
    this.leading,
    this.largeTitle = true,
    this.bottom,
    this.backgroundColor,
    this.automaticallyImplyLeading = true,
  });

  final String title;
  final Widget? trailing;
  final Widget? leading;
  final bool largeTitle;
  final PreferredSizeWidget? bottom;
  final Color? backgroundColor;
  final bool automaticallyImplyLeading;

  @override
  Widget build(BuildContext context) {
    if (PlatformHelper.isIOS(context)) {
      return CupertinoSliverNavigationBar(
        largeTitle: largeTitle ? Text(title) : null,
        middle: largeTitle ? null : Text(title),
        trailing: trailing,
        leading: leading,
        backgroundColor: backgroundColor ?? CupertinoColors.systemBackground,
        bottom: bottom,
        automaticallyImplyLeading: automaticallyImplyLeading,
      );
    }

    return SliverAppBar(
      title: Text(title),
      actions: trailing != null ? [trailing!] : null,
      leading: leading,
      floating: true,
      snap: true,
      bottom: bottom,
      backgroundColor: backgroundColor,
      automaticallyImplyLeading: automaticallyImplyLeading,
    );
  }
}
