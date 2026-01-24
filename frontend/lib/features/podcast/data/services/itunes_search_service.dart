import 'dart:async';
import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../models/podcast_search_model.dart';
import '../../../../core/utils/app_logger.dart' as logger;

/// iTunes Search Service
///
/// 直接调用 iTunes Search API 和 Lookup API，无需后端代理
class ITunesSearchService {
  final Dio _dio;

  // 缓存过期时间（1小时）
  static const Duration _cacheExpiration = Duration(hours: 1);

  // 缓存存储
  final Map<String, _CachedResponse> _cache = {};

  ITunesSearchService({Dio? dio}) : _dio = dio ?? Dio() {
    // 配置 Dio
    _dio.options = BaseOptions(
      connectTimeout: const Duration(seconds: 30),
      receiveTimeout: const Duration(seconds: 30),
      sendTimeout: const Duration(seconds: 30),
      headers: {
        'Content-Type': 'application/json',
      },
      // 禁用自动重试，以便更好地捕获错误
      validateStatus: (status) => status != null && status < 500,
    );
  }

  /// Factory constructor for Riverpod provider
  factory ITunesSearchService.ref(Ref ref) {
    return ITunesSearchService();
  }

  /// 搜索播客
  ///
  /// 使用 iTunes Search API 搜索播客
  ///
  /// Parameters:
  /// - [term] 搜索关键词（必需，会自动 URL 编码）
  /// - [country] 国家代码（默认 'cn'）
  /// - [limit] 返回结果数量（默认 25，最大 50）
  Future<ITunesSearchResponse> searchPodcasts({
    required String term,
    PodcastCountry country = PodcastCountry.china,
    int limit = 25,
  }) async {
    // 参数验证
    if (term.trim().isEmpty) {
      return const ITunesSearchResponse(
        resultCount: 0,
        results: [],
      );
    }

    if (limit < 1 || limit > 50) {
      limit = 25;
    }

    // 生成缓存键
    final cacheKey = 'search_${country.code}_$term${'_limit$limit'}';

    // 检查缓存
    final cachedResponse = _getCachedResponse(cacheKey);
    if (cachedResponse != null) {
      logger.AppLogger.debug('📦 Cache hit for iTunes search: $term');
      return cachedResponse;
    }

    try {
      final url = 'https://itunes.apple.com/search';
      final queryParams = {
        'term': term,
        'media': 'podcast',
        'entity': 'podcast',
        'country': country.code,
        'limit': limit,
      };

      logger.AppLogger.debug('🔍 Searching iTunes for: "$term"');
      logger.AppLogger.debug('   URL: $url');
      logger.AppLogger.debug('   Country: ${country.code}');
      logger.AppLogger.debug('   Limit: $limit');

      final response = await _dio.get(
        url,
        queryParameters: queryParams,
      );

      if (response.statusCode == 200) {
        // Debug: 打印原始响应类型
        logger.AppLogger.debug('📦 Response data type: ${response.data.runtimeType}');

        // 处理响应数据（可能是 String 或 Map）
        final Map<String, dynamic> data;
        if (response.data is String) {
          // 如果是字符串，需要手动解析 JSON
          logger.AppLogger.debug('📦 Parsing JSON from string...');
          data = jsonDecode(response.data as String) as Map<String, dynamic>;
        } else if (response.data is Map) {
          // 如果已经是 Map，直接使用
          data = response.data as Map<String, dynamic>;
        } else {
          throw Exception('Unexpected response type: ${response.data.runtimeType}');
        }

        final itunesResponse = ITunesSearchResponse.fromJson(data);

        logger.AppLogger.debug('✅ Found ${itunesResponse.resultCount} podcasts');

        // 缓存响应
        _setCachedResponse(cacheKey, itunesResponse);

        return itunesResponse;
      } else {
        final errorMsg = 'iTunes API returned status ${response.statusCode}';
        logger.AppLogger.debug('❌ $errorMsg');
        throw Exception(errorMsg);
      }
    } on DioException catch (dioError) {
      // 详细的 Dio 错误处理
      String errorMsg;
      switch (dioError.type) {
        case DioExceptionType.connectionTimeout:
          errorMsg = 'Connection timeout. Please check your network or try using a VPN.';
          logger.AppLogger.debug('❌ Connection Timeout: ${dioError.message}');
          break;
        case DioExceptionType.sendTimeout:
          errorMsg = 'Send timeout. Please try again.';
          logger.AppLogger.debug('❌ Send Timeout: ${dioError.message}');
          break;
        case DioExceptionType.receiveTimeout:
          errorMsg = 'Receive timeout. Server response too slow.';
          logger.AppLogger.debug('❌ Receive Timeout: ${dioError.message}');
          break;
        case DioExceptionType.badResponse:
          errorMsg = 'Server error: ${dioError.response?.statusCode}';
          logger.AppLogger.debug('❌ Bad Response: ${dioError.response?.statusCode}');
          break;
        case DioExceptionType.cancel:
          errorMsg = 'Request was cancelled.';
          logger.AppLogger.debug('❌ Request Cancelled');
          break;
        case DioExceptionType.connectionError:
          errorMsg = 'Connection failed. iTunes API may be blocked in your region. Try using a VPN.';
          logger.AppLogger.debug('❌ Connection Error: ${dioError.message}');
          logger.AppLogger.debug('   In China, iTunes API may require a VPN to access.');
          break;
        default:
          errorMsg = 'Network error: ${dioError.message}';
          logger.AppLogger.debug('❌ Network Error: ${dioError.message}');
      }
      throw Exception(errorMsg);
    } catch (error) {
      logger.AppLogger.debug('❌ iTunes search failed: $error');
      rethrow;
    }
  }

  /// 查询播客详情
  ///
  /// 使用 iTunes Lookup API 根据 iTunes ID 查询播客详细信息
  ///
  /// Parameters:
  /// - [itunesId] iTunes 播客 ID（必需）
  /// - [country] 国家代码（默认 'cn'）
  Future<PodcastSearchResult?> lookupPodcast({
    required int itunesId,
    PodcastCountry country = PodcastCountry.china,
  }) async {
    // 生成缓存键
    final cacheKey = 'lookup_${country.code}_$itunesId';

    // 检查缓存
    final cachedResponse = _getCachedResponse(cacheKey);
    if (cachedResponse != null && cachedResponse.results.isNotEmpty) {
      logger.AppLogger.debug('📦 Cache hit for iTunes lookup: $itunesId');
      return cachedResponse.results.first;
    }

    try {
      logger.AppLogger.debug('🔍 Looking up iTunes ID: $itunesId (country: ${country.code})');

      final response = await _dio.get(
        'https://itunes.apple.com/lookup',
        queryParameters: {
          'id': itunesId,
          'country': country.code,
        },
      );

      if (response.statusCode == 200) {
        final data = response.data as Map<String, dynamic>;
        final itunesResponse = ITunesSearchResponse.fromJson(data);

        if (itunesResponse.results.isNotEmpty) {
          final result = itunesResponse.results.first;
          logger.AppLogger.debug('✅ Found podcast: ${result.collectionName}');

          // 缓存响应
          _setCachedResponse(cacheKey, itunesResponse);

          return result;
        } else {
          logger.AppLogger.debug('⚠️ No podcast found for iTunes ID: $itunesId');
          return null;
        }
      } else {
        throw Exception('iTunes API returned status ${response.statusCode}');
      }
    } catch (error) {
      logger.AppLogger.debug('❌ iTunes lookup failed: $error');
      rethrow;
    }
  }

  /// 从缓存获取响应
  ITunesSearchResponse? _getCachedResponse(String key) {
    final cached = _cache[key];
    if (cached != null && !cached.isExpired) {
      return cached.response;
    }
    // 移除过期缓存
    _cache.remove(key);
    return null;
  }

  /// 设置缓存
  void _setCachedResponse(String key, ITunesSearchResponse response) {
    _cache[key] = _CachedResponse(
      response: response,
      timestamp: DateTime.now(),
    );
  }

  /// 清除所有缓存
  void clearCache() {
    _cache.clear();
    logger.AppLogger.debug('🗑️ iTunes search cache cleared');
  }

  /// 清除过期缓存
  void clearExpiredCache() {
    final now = DateTime.now();
    _cache.removeWhere((key, cached) {
      final isExpired = now.difference(cached.timestamp) > _cacheExpiration;
      if (isExpired) {
        logger.AppLogger.debug('🗑️ Removed expired cache: $key');
      }
      return isExpired;
    });
  }
}

/// 缓存响应包装类
class _CachedResponse {
  final ITunesSearchResponse response;
  final DateTime timestamp;

  _CachedResponse({
    required this.response,
    required this.timestamp,
  });

  bool get isExpired {
    return DateTime.now().difference(timestamp) > ITunesSearchService._cacheExpiration;
  }
}
