import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:personal_ai_assistant/core/network/etag_cache_service.dart';

Response<dynamic> _buildResponse(String path) {
  return Response<dynamic>(
    requestOptions: RequestOptions(path: path, method: 'GET'),
    statusCode: 200,
    data: {'path': path},
  );
}

void main() {
  group('ETagCacheService', () {
    test('evicts least recently used entry when max entries exceeded', () {
      final cache = ETagCacheService(maxEntries: 2);

      cache.setETag('k1', 'etag-1', _buildResponse('/k1'));
      cache.setETag('k2', 'etag-2', _buildResponse('/k2'));

      // Touch k1 so k2 becomes the least recently used entry.
      expect(cache.getETag('k1'), 'etag-1');

      cache.setETag('k3', 'etag-3', _buildResponse('/k3'));

      expect(cache.getETag('k1'), 'etag-1');
      expect(cache.getETag('k2'), isNull);
      expect(cache.getETag('k3'), 'etag-3');
    });

    test('expires entries based on default ttl', () async {
      final cache = ETagCacheService(
        maxEntries: 8,
        defaultTtl: const Duration(milliseconds: 20),
      );

      cache.setETag('expiring', 'etag-expiring', _buildResponse('/expiring'));
      expect(cache.getETag('expiring'), 'etag-expiring');

      await Future<void>.delayed(const Duration(milliseconds: 35));
      expect(cache.getETag('expiring'), isNull);
      expect(cache.getCachedResponse('expiring'), isNull);
    });

    test('generateKey keeps query parameters order-independent', () {
      final cache = ETagCacheService();
      final first = RequestOptions(
        path: '/episodes',
        method: 'GET',
        queryParameters: {'b': 2, 'a': 1},
      );
      final second = RequestOptions(
        path: '/episodes',
        method: 'GET',
        queryParameters: {'a': 1, 'b': 2},
      );

      expect(cache.generateKey(first), cache.generateKey(second));
    });
  });
}

