import 'dart:async' as async;
import 'package:flutter/foundation.dart';

/// Authentication event type
enum AuthEventType {
  /// Token was cleared (user needs to re-login)
  tokenCleared,
  /// Token was refreshed successfully
  tokenRefreshed,
}

/// Authentication event data
class AuthEvent {
  final AuthEventType type;
  final String? message;
  final DateTime timestamp;

  AuthEvent({
    required this.type,
    this.message,
    DateTime? timestamp,
  }) : timestamp = timestamp ?? DateTime.now();

  @override
  String toString() {
    return 'AuthEvent{type: $type, message: $message, timestamp: $timestamp}';
  }
}

/// Global authentication event notifier
///
/// This allows different parts of the app to communicate about
/// authentication state changes without creating circular dependencies.
///
/// **Lifecycle Notes:**
/// - This is a singleton that lives for the app's lifetime
/// - Stream listeners are tracked for debugging
/// - The stream is a broadcast stream, so multiple listeners are supported
/// - Call dispose() only when the app is shutting down
///
/// Usage:
/// ```dart
/// // Listen to auth events
/// authEventStream.listen((event) {
///   if (event.type == AuthEventType.tokenCleared) {
///     // Update auth state
///   }
/// });
///
/// // Broadcast auth event
/// AuthEventNotifier.instance.notify(AuthEvent(
///   type: AuthEventType.tokenCleared,
///   message: 'Token expired',
/// ));
///
/// // Debug info (check for listener leaks)
/// debugPrint(AuthEventNotifier.instance.debugInfo);
/// ```
class AuthEventNotifier {
  AuthEventNotifier._privateConstructor();

  static final AuthEventNotifier _instance = AuthEventNotifier._privateConstructor();

  /// Global singleton instance
  static AuthEventNotifier get instance => _instance;

  final _controller = async.StreamController<AuthEvent>.broadcast();
  int _listenerCount = 0;

  /// Stream of authentication events
  async.Stream<AuthEvent> get authEventStream {
    final stream = _controller.stream;
    // Track listener count for debugging
    stream.listen(
      (_) {},
      onDone: () {
        _listenerCount = _listenerCount > 0 ? _listenerCount - 1 : 0;
      },
      onError: (_) {},
    );
    return stream;
  }

  /// Debug information about active listeners
  ///
  /// Use this to check for listener leaks:
  /// ```dart
  /// debugPrint(AuthEventNotifier.instance.debugInfo);
  /// ```
  String get debugInfo => 'Active listeners: $_listenerCount';

  /// Broadcast an authentication event
  void notify(AuthEvent event) {
    if (kDebugMode) {
      debugPrint('🔔 [AuthEvent] ${event.type}: ${event.message ?? "no message"}');
    }
    if (!_controller.isClosed) {
      _controller.add(event);
    }
  }

  /// Dispose the stream controller
  void dispose() {
    if (!_controller.isClosed) {
      _controller.close();
    }
  }
}
