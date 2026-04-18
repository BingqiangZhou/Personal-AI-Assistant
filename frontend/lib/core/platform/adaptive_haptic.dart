import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Adaptive haptic feedback that provides platform-aware vibration.
///
/// Uses Flutter's HapticFeedback API which works on both iOS and Android.
/// Desktop platforms silently ignore haptic calls.
class AdaptiveHaptic {
  AdaptiveHaptic._();

  /// Light impact feedback for subtle interactions.
  ///
  /// Use for: tab switching, list item taps, slider movements.
  static void lightImpact() {
    try {
      HapticFeedback.lightImpact();
    } catch (e) {
      debugPrint('[AdaptiveHaptic] lightImpact failed: $e');
    }
  }

  /// Medium impact feedback for confirmations.
  ///
  /// Use for: like/favorite actions, download completion, successful operations.
  static void mediumImpact() {
    try {
      HapticFeedback.mediumImpact();
    } catch (e) {
      debugPrint('[AdaptiveHaptic] mediumImpact failed: $e');
    }
  }

  /// Heavy impact feedback for important actions.
  ///
  /// Use for: delete actions, major confirmations.
  static void heavyImpact() {
    try {
      HapticFeedback.heavyImpact();
    } catch (e) {
      debugPrint('[AdaptiveHaptic] heavyImpact failed: $e');
    }
  }

  /// Selection click feedback for precise interactions.
  ///
  /// Use for: slider tick marks, picker selections.
  static void selectionClick() {
    try {
      HapticFeedback.selectionClick();
    } catch (e) {
      debugPrint('[AdaptiveHaptic] selectionClick failed: $e');
    }
  }

  /// Notification success feedback.
  ///
  /// Use for: login success, subscription confirmations.
  static void notificationSuccess() {
    try {
      HapticFeedback.successNotification();
    } catch (e) {
      debugPrint('[AdaptiveHaptic] notificationSuccess failed: $e');
    }
  }
}
