import 'package:flutter/foundation.dart';

@immutable
class AppLoggerConfig {
  final bool debugEnabled;
  final bool infoEnabled;
  final bool warningEnabled;
  final bool errorEnabled;

  const AppLoggerConfig({
    required this.debugEnabled,
    required this.infoEnabled,
    required this.warningEnabled,
    required this.errorEnabled,
  });

  const AppLoggerConfig.debug()
    : debugEnabled = true,
      infoEnabled = true,
      warningEnabled = true,
      errorEnabled = true;

  const AppLoggerConfig.production()
    : debugEnabled = false,
      infoEnabled = false,
      warningEnabled = false,
      errorEnabled = true;

  const AppLoggerConfig.silent()
    : debugEnabled = false,
      infoEnabled = false,
      warningEnabled = false,
      errorEnabled = false;

  AppLoggerConfig copyWith({
    bool? debugEnabled,
    bool? infoEnabled,
    bool? warningEnabled,
    bool? errorEnabled,
  }) {
    return AppLoggerConfig(
      debugEnabled: debugEnabled ?? this.debugEnabled,
      infoEnabled: infoEnabled ?? this.infoEnabled,
      warningEnabled: warningEnabled ?? this.warningEnabled,
      errorEnabled: errorEnabled ?? this.errorEnabled,
    );
  }
}

class AppLogger {
  AppLogger._();

  static AppLoggerConfig _config = const AppLoggerConfig.production();

  static AppLoggerConfig get config => _config;

  static void configure(AppLoggerConfig config) {
    _config = config;
  }

  static void resetToDefault() {
    _config = const AppLoggerConfig.production();
  }

  static void debug(String message, {String? tag}) {
    if (!_config.debugEnabled) {
      return;
    }
    debugPrint('${_prefix(tag)}$message');
  }

  static void info(String message, {String? tag}) {
    if (!_config.infoEnabled) {
      return;
    }
    debugPrint('${_prefix(tag)}INFO: $message');
  }

  static void warning(String message, {String? tag}) {
    if (!_config.warningEnabled) {
      return;
    }
    debugPrint('${_prefix(tag)}WARN: $message');
  }

  static void error(
    String message, {
    Object? error,
    StackTrace? stackTrace,
    String? tag,
  }) {
    if (!_config.errorEnabled) {
      return;
    }
    final prefix = _prefix(tag);
    debugPrint('${prefix}ERROR: $message');
    if (error != null) {
      debugPrint('$prefix  Error: $error');
    }
    if (stackTrace != null) {
      debugPrint('$prefix  StackTrace:\n$stackTrace');
    }
  }

  static void network(String method, String url, {dynamic data, String? tag}) {
    if (!_config.debugEnabled) {
      return;
    }
    final prefix = _prefix(tag);
    debugPrint('${prefix}NETWORK: $method $url');
    if (data != null) {
      debugPrint('$prefix  Data: $data');
    }
  }

  static void networkResponse(
    String url,
    int statusCode, {
    dynamic data,
    String? tag,
  }) {
    if (!_config.debugEnabled) {
      return;
    }
    final prefix = _prefix(tag);
    debugPrint('${prefix}NETWORK_RESPONSE: $url - $statusCode');
    if (data != null) {
      debugPrint('$prefix  Response: $data');
    }
  }

  static void performance(String operation, Duration duration, {String? tag}) {
    if (!_config.debugEnabled) {
      return;
    }
    debugPrint(
      '${_prefix(tag)}PERF: $operation took ${duration.inMilliseconds}ms',
    );
  }

  static String _prefix(String? tag) => tag != null ? '[$tag] ' : '';
}

typedef Log = AppLogger;
