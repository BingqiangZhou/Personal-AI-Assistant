import 'dart:async';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:get_it/get_it.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Import the new AppConfig with dynamic baseUrl support
import '../../core/app/config/app_config.dart' as config;
import '../constants/app_constants.dart' as constants;
import 'exceptions/network_exceptions.dart';

final sl = GetIt.instance;

class DioClient {
  late final Dio _dio;
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  // Token refresh state - use Completer for proper synchronization
  Completer<bool>? _refreshCompleter;

  // Storage key for custom backend server base URL
  static const String _serverBaseUrlKey = 'server_base_url';

  DioClient() {
    // Initialize with default/empty baseUrl first
    // The actual baseUrl will be applied by _applySavedBaseUrl()
    _dio = Dio(BaseOptions(
      baseUrl: '',  // Will be set by _applySavedBaseUrl
      headers: constants.ApiConstants.headers,
      connectTimeout: Duration(milliseconds: constants.ApiConstants.connectTimeout.inMilliseconds),
      receiveTimeout: Duration(milliseconds: constants.ApiConstants.receiveTimeout.inMilliseconds),
      sendTimeout: Duration(milliseconds: constants.ApiConstants.sendTimeout.inMilliseconds),
    ));

    // Add interceptors
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: _onRequest,
        onResponse: _onResponse,
        onError: _onError,
      ),
    );

    // Apply saved baseUrl synchronously before returning
    _initializeBaseUrl();
  }

  /// Initialize baseUrl from saved storage or default config
  /// This must be called synchronously during construction
  void _initializeBaseUrl() {
    // Try to get saved URL synchronously from AppConfig first
    // AppConfig.setServerBaseUrl() should have been called during app init
    final savedBaseUrl = config.AppConfig.serverBaseUrl;
    final apiBaseUrl = savedBaseUrl.isNotEmpty
        ? '$savedBaseUrl/api/v1'
        : '${config.AppConfig.serverBaseUrl}/api/v1';

    _dio.options.baseUrl = apiBaseUrl;
    debugPrint('🔧 [DioClient] Initialized with baseUrl: $apiBaseUrl');

    // Apply any saved URL from storage asynchronously to ensure it's up to date
    _applySavedBaseUrl();
  }

  Dio get dio => _dio;

  /// Update the base URL dynamically
  /// This allows changing the API server at runtime without restarting the app
  void updateBaseUrl(String newBaseUrl) {
    _dio.options.baseUrl = newBaseUrl;
    debugPrint('🔄 [DioClient] Base URL updated to: $newBaseUrl');
  }

  /// Get the current base URL
  String get currentBaseUrl => _dio.options.baseUrl;

  /// Apply saved baseUrl from local storage (called during initialization)
  Future<void> _applySavedBaseUrl() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final savedUrl = prefs.getString(_serverBaseUrlKey);
      if (savedUrl != null && savedUrl.isNotEmpty) {
        // Normalize URL (remove trailing slashes, /api/v1 suffix)
        var normalizedUrl = savedUrl.trim();
        while (normalizedUrl.endsWith('/')) {
          normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 1);
        }
        // Remove /api/v1 suffix if present (7 characters)
        if (normalizedUrl.endsWith('/api/v1')) {
          normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length - 7);
        } else if (normalizedUrl.contains('/api/v1/')) {
          normalizedUrl = normalizedUrl.replaceFirst('/api/v1/', '/');
        }

        // Apply with /api/v1 suffix
        updateBaseUrl('$normalizedUrl/api/v1');
        debugPrint('📥 [DioClient] Applied saved backend API baseUrl: $savedUrl');
      }
    } catch (e) {
      debugPrint('⚠️ [DioClient] Failed to apply saved baseUrl: $e');
    }
  }

  Future<void> _onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    // 🔍 DEBUG: 输出完整的请求URL
    final fullUrl = '${_dio.options.baseUrl}/${options.path}';
    debugPrint('🌐 [API REQUEST] ${options.method} $fullUrl');
    if (options.data != null) {
      debugPrint('   Data: ${options.data}');
    }
    if (options.queryParameters.isNotEmpty) {
      debugPrint('   Query: ${options.queryParameters}');
    }

    // Only add token if not already set (e.g., by retry logic)
    if (!options.headers.containsKey('Authorization')) {
      final token = await _secureStorage.read(key: config.AppConstants.accessTokenKey);
      if (token != null) {
        options.headers['Authorization'] = 'Bearer $token';
        debugPrint('   ✅ Token added: ${token.substring(0, 20)}...');
      } else {
        debugPrint('   ⚠️ No token found');
      }
    }

    handler.next(options);
  }

  void _onResponse(
    Response response,
    ResponseInterceptorHandler handler,
  ) {
    // 🔍 Debug: 打印AI Summary相关响应
    if (response.requestOptions.path.contains('/episodes/')) {
      final data = response.data;
      if (data is Map && data.containsKey('ai_summary')) {
        debugPrint('🔍 [API RESPONSE] Episode ${data['id']} has ai_summary: ${data['ai_summary'] != null ? "YES (${data['ai_summary'].length} chars)" : "NO"}');
      }
    }
    handler.next(response);
  }

  void _onError(
    DioException error,
    ErrorInterceptorHandler handler,
  ) async {
    // 🔍 DEBUG: 输出错误请求的完整URL
    final errorUrl = '${error.requestOptions.baseUrl}/${error.requestOptions.path}';
    debugPrint('❌ [API ERROR] ${error.requestOptions.method} $errorUrl');
    debugPrint('   Type: ${error.type}');
    debugPrint('   Message: ${error.message}');

    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
        debugPrint('   ⏱️ Timeout Error');
        handler.reject(
          DioException(
            requestOptions: error.requestOptions,
            type: DioExceptionType.unknown,
            error: NetworkException('Connection timeout'),
          ),
        );
        break;
      case DioExceptionType.badResponse:
        final statusCode = error.response?.statusCode;
        if (statusCode != null) {
          if (statusCode == 401) {
            // Log 401 error details
            debugPrint('❌ 401 Error: ${error.requestOptions.method} ${error.requestOptions.path}');
            debugPrint('   Response: ${error.response?.data}');

            // Check if this is a refresh token request to avoid infinite loop
            final isRefreshRequest = error.requestOptions.path.contains('/auth/refresh');

            if (!isRefreshRequest) {
              // Try to refresh the token
              final newToken = await _refreshToken();

              if (newToken != null) {
                // Retry the original request with new token
                try {
                  final response = await _retryRequest(error.requestOptions, newToken);
                  handler.resolve(response);
                  return;
                } on DioException catch (retryError) {
                  // Check if retry still fails with 401
                  if (retryError.response?.statusCode == 401) {
                    debugPrint('❌ Retry still returns 401, clearing tokens');
                    await _clearTokens();
                  }
                  // Pass the retry error to handler (could be 404, 403, etc.)
                  debugPrint('⚠️ Retry failed with status: ${retryError.response?.statusCode}');
                  handler.reject(retryError);
                  return;
                } catch (e) {
                  // Unexpected error during retry
                  debugPrint('❌ Unexpected error during retry: $e');
                  await _clearTokens();
                  handler.reject(error);
                  return;
                }
              } else {
                // Refresh failed, clear tokens and reject
                debugPrint('❌ Token refresh failed, clearing tokens');
                await _clearTokens();
              }
            }

            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: AuthenticationException.fromDioError(error),
              ),
            );
          } else if (statusCode == 403) {
            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: AuthorizationException.fromDioError(error),
              ),
            );
          } else if (statusCode == 404) {
            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: NotFoundException.fromDioError(error),
              ),
            );
          } else if (statusCode == 409) {
            // Debug 409 errors
            debugPrint('=== Dio Client 409 Error ===');
            debugPrint('Response data: ${error.response?.data}');
            final conflictError = ConflictException.fromDioError(error);
            debugPrint('ConflictException message: ${conflictError.message}');
            debugPrint('============================');

            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: conflictError,
              ),
            );
          } else if (statusCode == 422) {
            // Debug 422 errors
            debugPrint('=== Dio Client 422 Error ===');
            debugPrint('Response data: ${error.response?.data}');
            final validationError = ValidationException.fromDioError(error);
            debugPrint('ValidationException message: ${validationError.message}');
            debugPrint('ValidationException fieldErrors: ${validationError.fieldErrors}');
            debugPrint('============================');

            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: validationError,
              ),
            );
          } else {
            handler.reject(
              DioException(
                requestOptions: error.requestOptions,
                response: error.response,
                type: DioExceptionType.badResponse,
                error: ServerException.fromDioError(error),
              ),
            );
          }
        } else {
          handler.reject(
            DioException(
              requestOptions: error.requestOptions,
              type: DioExceptionType.unknown,
              error: const UnknownException('Unknown error occurred'),
            ),
          );
        }
        break;
      default:
        handler.reject(
          DioException(
            requestOptions: error.requestOptions,
            type: DioExceptionType.unknown,
            error: NetworkException.fromDioError(error),
          ),
        );
    }
  }

  // Token refresh methods
  Future<String?> _refreshToken() async {
    // Store completer in local variable to avoid race condition
    final completer = _refreshCompleter;
    if (completer != null && !completer.isCompleted) {
      debugPrint('🔄 Token refresh already in progress, waiting...');
      final success = await completer.future;
      if (success) {
        // Return the token from storage for waiting requests
        return await _secureStorage.read(key: config.AppConstants.accessTokenKey);
      }
      return null;
    }

    // Start new refresh
    debugPrint('🔄 Starting new token refresh...');
    _refreshCompleter = Completer<bool>();
    final currentCompleter = _refreshCompleter!;

    try {
      final refreshToken = await _secureStorage.read(key: config.AppConstants.refreshTokenKey);
      if (refreshToken == null) {
        debugPrint('❌ No refresh token found in storage');
        currentCompleter.complete(false);
        await _clearTokens();
        return null;
      }

      debugPrint('📤 Sending refresh token request...');

      final response = await _dio.post(
        '/auth/refresh',
        data: {'refresh_token': refreshToken},
        options: Options(
          headers: {'Content-Type': 'application/json'},
        ),
      );

      if (response.statusCode == 200 && response.data != null) {
        final newAccessToken = response.data['access_token'];
        final newRefreshToken = response.data['refresh_token'];

        if (newAccessToken != null) {
          await _secureStorage.write(key: config.AppConstants.accessTokenKey, value: newAccessToken);
          if (newRefreshToken != null) {
            await _secureStorage.write(key: config.AppConstants.refreshTokenKey, value: newRefreshToken);
          }

          debugPrint('✅ Token refresh successful - New token: ${newAccessToken.substring(0, 20)}...');
          currentCompleter.complete(true);
          return newAccessToken;
        }
      }

      debugPrint('❌ Token refresh failed: invalid response format');
      currentCompleter.complete(false);
      await _clearTokens();
      return null;
    } catch (e) {
      // Better error handling with detailed logging
      if (e is DioException) {
        final statusCode = e.response?.statusCode;
        final responseData = e.response?.data;

        debugPrint('❌ Token refresh failed:');
        debugPrint('   Status: $statusCode');
        debugPrint('   Type: ${e.type}');
        debugPrint('   Response: $responseData');

        // If refresh token is invalid (404, 401, or specific error), clear tokens
        if (statusCode == 404 || statusCode == 401 ||
            (responseData is Map && responseData['detail']?.toString().toLowerCase().contains('invalid') == true)) {
          debugPrint('🔓 Refresh token invalid, clearing all tokens');
          await _clearTokens();
        }
      } else {
        debugPrint('❌ Token refresh failed with unexpected error: $e');
        // Clear tokens on any unexpected error
        await _clearTokens();
      }

      currentCompleter.complete(false);
      return null;
    } finally {
      // Reset completer immediately
      _refreshCompleter = null;
    }
  }

  Future<Response> _retryRequest(RequestOptions options, String token) async {
    // Create a new headers map, removing any existing Authorization header (case-insensitive)
    // and adding the new one with the correct token
    final newHeaders = Map<String, dynamic>.from(options.headers);
    newHeaders.removeWhere((key, value) => key.toLowerCase() == 'authorization');
    newHeaders['Authorization'] = 'Bearer $token';

    // Use copyWith to create a new RequestOptions with updated headers
    final newOptions = options.copyWith(headers: newHeaders);

    debugPrint('🔄 Retrying ${options.method} ${options.path} with new token: ${token.substring(0, 20)}...');
    debugPrint('   Query: ${newOptions.queryParameters}');
    debugPrint('   Data: ${newOptions.data}');

    try {
      final response = await _dio.fetch(newOptions);
      debugPrint('✅ Retry successful: ${response.statusCode}');
      return response;
    } catch (e) {
      debugPrint('❌ Retry failed: $e');
      rethrow;
    }
  }

  Future<void> _clearTokens() async {
    await _secureStorage.delete(key: config.AppConstants.accessTokenKey);
    await _secureStorage.delete(key: config.AppConstants.refreshTokenKey);
    await _secureStorage.delete(key: config.AppConstants.userProfileKey);
  }

  // HTTP methods
  Future<Response> get(String path, {Map<String, dynamic>? queryParameters}) async {
    return _dio.get(path, queryParameters: queryParameters);
  }

  Future<Response> post(String path, {dynamic data}) async {
    return _dio.post(path, data: data);
  }

  Future<Response> put(String path, {dynamic data}) async {
    return _dio.put(path, data: data);
  }

  Future<Response> delete(String path) async {
    return _dio.delete(path);
  }

  // Static factory method for ServiceLocator
  static Dio createDio() {
    return DioClient()._dio;
  }
}