import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:personal_ai_assistant/core/platform/platform_helper.dart';

/// Adaptive text field.
///
/// iOS: [CupertinoTextField] with bottom-border-only style.
/// Android: Material [TextField] with outlined decoration.
class AdaptiveTextField extends StatelessWidget {
  const AdaptiveTextField({
    super.key,
    this.controller,
    this.focusNode,
    this.decoration,
    this.placeholder,
    this.obscureText = false,
    this.onChanged,
    this.onSubmitted,
    this.enabled = true,
    this.maxLines = 1,
    this.keyboardType,
    this.textInputAction,
    this.autofocus = false,
  });

  final TextEditingController? controller;
  final FocusNode? focusNode;
  final InputDecoration? decoration;
  final String? placeholder;
  final bool obscureText;
  final ValueChanged<String>? onChanged;
  final ValueChanged<String>? onSubmitted;
  final bool enabled;
  final int? maxLines;
  final TextInputType? keyboardType;
  final TextInputAction? textInputAction;
  final bool autofocus;

  @override
  Widget build(BuildContext context) {
    if (PlatformHelper.isIOS(context)) {
      return CupertinoTextField(
        controller: controller,
        focusNode: focusNode,
        placeholder: placeholder,
        obscureText: obscureText,
        onChanged: onChanged,
        onSubmitted: onSubmitted,
        enabled: enabled,
        maxLines: maxLines,
        keyboardType: keyboardType,
        textInputAction: textInputAction,
        autofocus: autofocus,
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: CupertinoColors.tertiarySystemFill,
          borderRadius: BorderRadius.circular(10),
        ),
      );
    }

    return TextField(
      controller: controller,
      focusNode: focusNode,
      obscureText: obscureText,
      onChanged: onChanged,
      onSubmitted: onSubmitted,
      enabled: enabled,
      maxLines: maxLines,
      keyboardType: keyboardType,
      textInputAction: textInputAction,
      autofocus: autofocus,
      decoration: decoration ??
          InputDecoration(
            hintText: placeholder,
            border: const OutlineInputBorder(),
          ),
    );
  }
}
