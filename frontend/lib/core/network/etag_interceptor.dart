import 'package:dio/dio.dart';
import 'etag_cache_service.dart';
import '../utils/app_logger.dart' as logger;

/// ETag Interceptor for Dio
///
/// Handles HTTP ETag caching by:
/// 1. Adding If-None-Match header to requests with cached ETags
/// 2. Storing ETags from successful responses
/// 3. Handling 304 Not Modified responses by returning cached data
class ETagInterceptor extends Interceptor {
  final ETagCacheService _cacheService;
  final bool _enabled;

  /// Create ETag interceptor
  ///
  /// [cacheService] - Optional custom cache service (defaults to global singleton)
  /// [enabled] - Enable/disable ETag functionality
  ETagInterceptor({
    ETagCacheService? cacheService,
    bool enabled = true,
  })  : _cacheService = cacheService ?? etagCacheService,
        _enabled = enabled;

  @override
  void onRequest(RequestOptions options, RequestInterceptorHandler handler) {
    if (!_enabled) {
      handler.next(options);
      return;
    }

    // Only add ETag header for GET requests
    if (options.method.toUpperCase() == 'GET') {
      final key = _cacheService.generateKey(options);
      final etag = _cacheService.getETag(key);

      if (etag != null && etag.isNotEmpty) {
        options.headers['If-None-Match'] = etag;
        logger.AppLogger.debug('🏷️ [ETag] Adding If-None-Match: $etag for $key');
      }
    }

    handler.next(options);
  }

  @override
  void onResponse(Response response, ResponseInterceptorHandler handler) {
    if (!_enabled) {
      handler.next(response);
      return;
    }

    // Only process GET requests
    if (response.requestOptions.method.toUpperCase() != 'GET') {
      handler.next(response);
      return;
    }

    // Check for ETag header in response
    final etag = response.headers.value('etag');
    if (etag != null && etag.isNotEmpty) {
      final key = _cacheService.generateKey(response.requestOptions);

      // Store ETag and response
      _cacheService.setETag(key, etag, response);
      logger.AppLogger.debug('🏷️ [ETag] Cached: $etag for $key');
    }

    handler.next(response);
  }

  @override
  void onError(DioException err, ErrorInterceptorHandler handler) {
    if (!_enabled) {
      handler.next(err);
      return;
    }

    // Check for 304 Not Modified response
    if (err.response?.statusCode == 304) {
      final key = _cacheService.generateKey(err.requestOptions);
      final cached = _cacheService.getCachedResponse(key);

      if (cached != null) {
        // Update cached response with new headers from 304 response
        if (err.response?.headers != null) {
          err.response!.headers.forEach((name, values) {
            cached.headers.set(name, values);
          });
        }

        logger.AppLogger.debug('🏷️ [ETag] Using cached response for $key (304)');
        handler.resolve(cached);
        return;
      }

      logger.AppLogger.warning('🏷️ [ETag] 304 received but no cached response for $key');
    }

    handler.next(err);
  }

  /// Clear all cached ETags and responses
  void clearCache() {
    _cacheService.clearAll();
    logger.AppLogger.debug('🏷️ [ETag] Cache cleared');
  }

  /// Clear cached ETag for specific key
  void clearKey(String key) {
    _cacheService.clearETag(key);
    logger.AppLogger.debug('🏷️ [ETag] Cleared key: $key');
  }

  /// Clear cached ETags matching a pattern
  void clearPattern(String pattern) {
    _cacheService.clearPattern(pattern);
    logger.AppLogger.debug('🏷️ [ETag] Cleared pattern: $pattern');
  }

  /// Get cache statistics
  Map<String, dynamic> getStats() {
    return {
      'enabled': _enabled,
      'cacheSize': _cacheService.cacheSize,
      'keys': _cacheService.cacheKeys,
    };
  }
}
