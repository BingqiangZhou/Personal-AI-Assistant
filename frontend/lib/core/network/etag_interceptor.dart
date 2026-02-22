import 'package:dio/dio.dart';

import '../utils/app_logger.dart' as logger;
import 'etag_cache_service.dart';

/// ETag Interceptor for Dio
///
/// Handles HTTP ETag caching by:
/// 1. Adding If-None-Match header to requests with cached ETags.
/// 2. Storing ETags from successful responses.
/// 3. Returning cached data on 304 Not Modified.
/// 4. Fast-serving fresh cached responses during max-age window.
class ETagInterceptor extends Interceptor {
  final ETagCacheService _cacheService;
  final bool _enabled;

  /// Create ETag interceptor.
  ///
  /// [cacheService] optional custom cache service.
  /// [enabled] enable or disable ETag behavior.
  ETagInterceptor({ETagCacheService? cacheService, bool enabled = true})
    : _cacheService = cacheService ?? etagCacheService,
      _enabled = enabled;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (!_enabled) {
      handler.next(options);
      return;
    }

    if (options.method.toUpperCase() != 'GET') {
      handler.next(options);
      return;
    }

    final key = _cacheService.generateKey(options);
    final freshCachedResponse = _cacheService.getFreshCachedResponse(key);

    // Fast path: serve local cache directly when still inside max-age window.
    if (!_shouldForceRevalidate(options) && freshCachedResponse != null) {
      logger.AppLogger.debug('[ETag] Using fresh local cache for $key');
      handler.resolve(freshCachedResponse);
      return;
    }

    final etag = _cacheService.getETag(key);
    if (etag != null && etag.isNotEmpty) {
      options.headers['If-None-Match'] = etag;
      logger.AppLogger.debug('[ETag] Adding If-None-Match: $etag for $key');
    }

    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (!_enabled) {
      handler.next(response);
      return;
    }

    if (response.requestOptions.method.toUpperCase() != 'GET') {
      handler.next(response);
      return;
    }

    final etag = response.headers.value('etag');
    if (etag != null && etag.isNotEmpty) {
      final key = _cacheService.generateKey(response.requestOptions);
      final maxAge = _extractMaxAge(response.headers.value('cache-control'));
      _cacheService.setETag(key, etag, response, maxAge: maxAge);
      logger.AppLogger.debug('[ETag] Cached: $etag for $key');
    }

    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (!_enabled) {
      handler.next(err);
      return;
    }

    if (err.response?.statusCode == 304) {
      final key = _cacheService.generateKey(err.requestOptions);
      final cached = _cacheService.getCachedResponse(key);

      if (cached != null) {
        if (err.response?.headers != null) {
          err.response!.headers.forEach((name, values) {
            cached.headers.set(name, values);
          });
        }
        logger.AppLogger.debug('[ETag] Using cached response for $key (304)');
        handler.resolve(cached);
        return;
      }

      logger.AppLogger.warning(
        '[ETag] 304 received but no cached response for $key',
      );
    }

    handler.next(err);
  }

  /// Clear all cached ETags and responses.
  void clearCache() {
    _cacheService.clearAll();
    logger.AppLogger.debug('[ETag] Cache cleared');
  }

  /// Clear cached ETag for specific key.
  void clearKey(String key) {
    _cacheService.clearETag(key);
    logger.AppLogger.debug('[ETag] Cleared key: $key');
  }

  /// Clear cached ETags matching a pattern.
  void clearPattern(String pattern) {
    _cacheService.clearPattern(pattern);
    logger.AppLogger.debug('[ETag] Cleared pattern: $pattern');
  }

  /// Get cache statistics.
  Map<String, dynamic> getStats() {
    return {
      'enabled': _enabled,
      'cacheSize': _cacheService.cacheSize,
      'keys': _cacheService.cacheKeys,
    };
  }

  bool _shouldForceRevalidate(RequestOptions options) {
    if (options.extra['etag_force_revalidate'] == true) {
      return true;
    }

    final cacheControl = options.headers['Cache-Control']?.toString();
    if (cacheControl != null) {
      final lower = cacheControl.toLowerCase();
      if (lower.contains('no-cache') ||
          lower.contains('no-store') ||
          lower.contains('max-age=0')) {
        return true;
      }
    }

    final pragma = options.headers['Pragma']?.toString().toLowerCase();
    return pragma == 'no-cache';
  }

  Duration? _extractMaxAge(String? cacheControl) {
    if (cacheControl == null || cacheControl.isEmpty) {
      return null;
    }

    final directives = cacheControl
        .split(',')
        .map((entry) => entry.trim().toLowerCase())
        .where((entry) => entry.isNotEmpty)
        .toList();

    if (directives.contains('no-store')) {
      return null;
    }

    for (final directive in directives) {
      if (directive.startsWith('max-age=')) {
        final raw = directive.substring('max-age='.length);
        final seconds = int.tryParse(raw);
        if (seconds == null) {
          return null;
        }
        return Duration(seconds: seconds);
      }
    }

    return null;
  }
}
