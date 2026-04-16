import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/platform/platform_helper.dart';

/// Adaptive list tile.
///
/// iOS: [CupertinoListTile] with Cupertino-style padding and dividers.
/// Android: Material [ListTile].
class AdaptiveListTile extends StatelessWidget {
  const AdaptiveListTile({
    required this.title,
    super.key,
    this.leading,
    this.subtitle,
    this.trailing,
    this.onTap,
    this.leadingToTitle,
  });

  final Widget? leading;
  final Widget title;
  final Widget? subtitle;
  final Widget? trailing;
  final VoidCallback? onTap;
  final double? leadingToTitle;

  @override
  Widget build(BuildContext context) {
    if (PlatformHelper.isIOS(context)) {
      return CupertinoListTile(
        leading: leading,
        title: DefaultTextStyle(
          style: CupertinoTheme.of(context).textTheme.textStyle,
          child: title,
        ),
        subtitle: subtitle,
        trailing: trailing,
        onTap: onTap,
        leadingToTitle: leadingToTitle ?? 16.0,
      );
    }

    return ListTile(
      leading: leading,
      title: title,
      subtitle: subtitle,
      trailing: trailing,
      onTap: onTap,
    );
  }
}
