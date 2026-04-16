import 'package:flutter/cupertino.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';

Page<T> adaptivePageTransition<T>({
  required Widget child,
  required ValueKey<String> pageKey,
  bool fullscreenDialog = false,
}) {
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
