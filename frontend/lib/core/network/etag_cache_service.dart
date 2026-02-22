import 'dart:collection';
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
  final LinkedHashMap<String, _ETagEntry> _cache = LinkedHashMap();
  final int _maxEntries;
  final Duration _defaultTtl;

  ETagCacheService({
    int maxEntries = 256,
    Duration defaultTtl = const Duration(hours: 1),
  }) : _maxEntries = maxEntries,
       _defaultTtl = defaultTtl;

  Duration _entryTtl(_ETagEntry entry) => entry.maxAge ?? _defaultTtl;

  bool _isExpired(_ETagEntry entry) {
    final age = DateTime.now().difference(entry.timestamp);
    return age > _entryTtl(entry);
  }

  void _evictExpired() {
    final expiredKeys = <String>[];
    _cache.forEach((key, entry) {
      if (_isExpired(entry)) {
        expiredKeys.add(key);
      }
    });
    for (final key in expiredKeys) {
      _cache.remove(key);
    }
  }

  void _touch(String key, _ETagEntry entry) {
    _cache.remove(key);
    _cache[key] = entry;
  }

  _ETagEntry? _getValidEntry(String key) {
    final entry = _cache[key];
    if (entry == null) {
      return null;
    }
    if (_isExpired(entry)) {
      _cache.remove(key);
      return null;
    }
    _touch(key, entry);
    return entry;
  }

  /// Get ETag for a given cache key
  String? getETag(String key) => _getValidEntry(key)?.etag;

  /// Get cached response for a given cache key
  Response? getCachedResponse(String key) => _getValidEntry(key)?.response;

  /// Get cached response only when entry is still fresh by max-age.
  ///
  /// Returns `null` when:
  /// - cache key does not exist
  /// - max-age is unavailable
  /// - max-age has expired
  Response? getFreshCachedResponse(String key) {
    final entry = _getValidEntry(key);
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
    final entry = _getValidEntry(key);
    if (entry == null) return false;

    if (maxAge != null) {
      final age = DateTime.now().difference(entry.timestamp);
      return age <= maxAge;
    }

    return true;
  }

  /// Set ETag and response for a given cache key
  void setETag(String key, String etag, Response response, {Duration? maxAge}) {
    _evictExpired();
    _cache.remove(key);
    _cache[key] = _ETagEntry(etag, response, maxAge: maxAge);
    while (_cache.length > _maxEntries) {
      _cache.remove(_cache.keys.first);
    }
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
    _evictExpired();
    final regex = RegExp(pattern);
    _cache.removeWhere((key, _) => regex.hasMatch(key));
  }

  /// Get number of cached entries
  int get cacheSize {
    _evictExpired();
    return _cache.length;
  }

  /// Get all cache keys
  List<String> get cacheKeys {
    _evictExpired();
    return _cache.keys.toList();
  }

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
