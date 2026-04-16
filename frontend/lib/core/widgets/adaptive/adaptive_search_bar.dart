import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/platform/platform_helper.dart';

/// Adaptive search bar.
///
/// iOS: [CupertinoSearchTextField] with rounded gray background.
/// Android: Material [SearchBar] with pill shape.
class AdaptiveSearchBar extends StatelessWidget {
  const AdaptiveSearchBar({
    super.key,
    this.controller,
    this.onChanged,
    this.onSubmitted,
    this.placeholder,
    this.autofocus = false,
    this.focusNode,
  });

  final TextEditingController? controller;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;
  final String? placeholder;
  final bool autofocus;
  final FocusNode? focusNode;

  @override
  Widget build(BuildContext context) {
    if (PlatformHelper.isIOS(context)) {
      return CupertinoSearchTextField(
        controller: controller,
        onChanged: onChanged,
        onSubmitted: onSubmitted,
        placeholder: placeholder,
        autofocus: autofocus,
        focusNode: focusNode,
        style: CupertinoTheme.of(context).textTheme.textStyle,
      );
    }

    return SearchBar(
      controller: controller,
      onChanged: onChanged,
      hintText: placeholder,
      autoFocus: autofocus,
      focusNode: focusNode,
      padding: const WidgetStatePropertyAll(
        EdgeInsets.symmetric(horizontal: 16),
      ),
    );
  }
}
