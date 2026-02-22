import 'dart:convert';
import 'package:dio/dio.dart';

/// Cache entry for ETag and response data
class _ETagEntry {
  final String etag;
  final Response response;
  final DateTime timestamp;
  final Duration? maxAge;

  _ETagEntry(this.etag, this.response, {this.maxAge})
    : timestamp = DateTime.now();
}

/// ETag Cache Service
///
/// Manages ETag storage and response caching for conditional requests.
/// Stores ETags and associated responses in memory.
class ETagCacheService {
  final Map<String, _ETagEntry> _cache = {};

  /// Get ETag for a given cache key
  String? getETag(String key) => _cache[key]?.etag;

  /// Get cached response for a given cache key
  Response? getCachedResponse(String key) => _cache[key]?.response;

  /// Get cached response only when entry is still fresh by max-age.
  ///
  /// Returns `null` when:
  /// - cache key does not exist
  /// - max-age is unavailable
  /// - max-age has expired
  Response? getFreshCachedResponse(String key) {
    final entry = _cache[key];
    if (entry == null) {
      return null;
    }

    final maxAge = entry.maxAge;
    if (maxAge == null || maxAge <= Duration.zero) {
      return null;
    }

    final age = DateTime.now().difference(entry.timestamp);
    if (age > maxAge) {
      _cache.remove(key);
      return null;
    }

    return entry.response;
  }

  /// Check if cache entry exists and is recent (within TTL)
  bool hasValidEntry(String key, {Duration? maxAge}) {
    final entry = _cache[key];
    if (entry == null) return false;

    if (maxAge != null) {
      final age = DateTime.now().difference(entry.timestamp);
      return age <= maxAge;
    }

    return true;
  }

  /// Set ETag and response for a given cache key
  void setETag(String key, String etag, Response response, {Duration? maxAge}) {
    _cache[key] = _ETagEntry(etag, response, maxAge: maxAge);
  }

  /// Clear ETag cache for a specific key
  void clearETag(String key) {
    _cache.remove(key);
  }

  /// Clear all ETag cache entries
  void clearAll() {
    _cache.clear();
  }

  /// Clear cache entries matching a pattern
  void clearPattern(String pattern) {
    final regex = RegExp(pattern);
    _cache.removeWhere((key, _) => regex.hasMatch(key));
  }

  /// Get number of cached entries
  int get cacheSize => _cache.length;

  /// Get all cache keys
  List<String> get cacheKeys => _cache.keys.toList();

  /// Generate cache key from RequestOptions
  String generateKey(RequestOptions options) {
    // Sort query parameters for consistent key generation
    final sortedParams = <String, dynamic>{};
    if (options.queryParameters.isNotEmpty) {
      final sortedKeys = options.queryParameters.keys.toList()..sort();
      for (final key in sortedKeys) {
        sortedParams[key] = options.queryParameters[key];
      }
    }

    // Create query string
    final queryString = sortedParams.entries
        .map((e) => '${e.key}=${_normalizeValue(e.value)}')
        .join('&');

    // Combine method, path, and query string
    return '${options.method}:${options.path}:$queryString';
  }

  /// Normalize query parameter value for consistent key generation
  String _normalizeValue(dynamic value) {
    if (value == null) return '';
    if (value is List || value is Map) {
      return jsonEncode(value);
    }
    return value.toString();
  }
}

/// Global singleton instance
final etagCacheService = ETagCacheService();
