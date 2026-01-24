import 'package:flutter/foundation.dart';

/// Application Logger / 应用日志系统
///
/// Provides conditional logging based on build mode.
/// Only logs in debug mode, silently ignores in production.
/// 根据构建模式提供条件化日志。调试模式下记录日志，生产模式下静默忽略。
class AppLogger {
  /// Private constructor to prevent instantiation
  AppLogger._();

  /// Log debug message / 记录调试信息
  ///
  /// Only logs in debug mode.
  ///仅在调试模式下记录
  static void debug(String message, {String? tag}) {
    if (kDebugMode) {
      final prefix = tag != null ? '[$tag] ' : '';
      debugPrint('$prefix$message');
    }
  }

  /// Log info message / 记录一般信息
  ///
  /// Only logs in debug mode.
  /// 仅在调试模式下记录
  static void info(String message, {String? tag}) {
    if (kDebugMode) {
      final prefix = tag != null ? '[$tag] ' : '';
      debugPrint('$prefixℹ️ $message');
    }
  }

  /// Log warning message / 记录警告信息
  ///
  /// Only logs in debug mode.
  /// 仅在调试模式下记录
  static void warning(String message, {String? tag}) {
    if (kDebugMode) {
      final prefix = tag != null ? '[$tag] ' : '';
      debugPrint('$prefix⚠️ $message');
    }
  }

  /// Log error message / 记录错误信息
  ///
  /// Always logs in all modes for critical errors.
  /// 在所有模式下都记录关键错误
  static void error(String message, {Object? error, StackTrace? stackTrace, String? tag}) {
    final prefix = tag != null ? '[$tag] ' : '';
    if (kDebugMode) {
      debugPrint('$prefix❌ $message');
      if (error != null) {
        debugPrint('$prefix  Error: $error');
      }
      if (stackTrace != null) {
        debugPrint('$prefix  StackTrace:\n$stackTrace');
      }
    } else {
      // In production, still log errors (could be sent to crash reporting service)
      // 生产环境仍然记录错误（可发送到崩溃报告服务）
      debugPrint('$prefix❌ $message');
    }
  }

  /// Log network request / 记录网络请求
  static void network(String method, String url, {dynamic data, String? tag}) {
    if (kDebugMode) {
      final prefix = tag != null ? '[$tag] ' : '';
      debugPrint('$prefix🌐 $method $url');
      if (data != null) {
        debugPrint('$prefix  Data: $data');
      }
    }
  }

  /// Log network response / 记录网络响应
  static void networkResponse(String url, int statusCode, {dynamic data, String? tag}) {
    if (kDebugMode) {
      final prefix = tag != null ? '[$tag] ' : '';
      final statusIcon = statusCode >= 200 && statusCode < 300 ? '✅' : '❌';
      debugPrint('$prefix$statusIcon $url - $statusCode');
      if (data != null && kDebugMode) {
        debugPrint('$prefix  Response: $data');
      }
    }
  }

  /// Log performance metric / 记录性能指标
  static void performance(String operation, Duration duration, {String? tag}) {
    if (kDebugMode) {
      final prefix = tag != null ? '[$tag] ' : '';
      final ms = duration.inMilliseconds;
      debugPrint('$prefix⏱️ $operation took ${ms}ms');
    }
  }
}

/// Shorthand for AppLogger.debug / AppLogger.debug 的简写
typedef Log = AppLogger;
