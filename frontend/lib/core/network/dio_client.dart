import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:get_it/get_it.dart';

import '../app/config/app_config.dart';
import 'exceptions/network_exceptions.dart';
import '../storage/secure_storage_service.dart';
import '../utils/logger.dart';

final sl = GetIt.instance;

class DioClient {
  late final Dio _dio;
  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage();

  // Token refresh state
  bool _isRefreshing = false;
  final List<Function()> _queuedRequests = [];

  DioClient() {
    _dio = Dio(BaseOptions(
      baseUrl: AppConstants.baseUrl,
      headers: ApiConstants.headers,
      connectTimeout: Duration(milliseconds: AppConstants.connectTimeout),
      receiveTimeout: Duration(milliseconds: AppConstants.receiveTimeout),
      sendTimeout: Duration(milliseconds: AppConstants.sendTimeout),
    ));

    // Add interceptors
    _dio.interceptors.add(
      InterceptorsWrapper(
        onRequest: _onRequest,
        onResponse: _onResponse,
        onError: _onError,
      ),
    );
  }

  Dio get dio => _dio;

  Future<void> _onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    // Add authentication token if available
    final token = await _secureStorage.read(key: AppConstants.accessTokenKey);
    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }

    handler.next(options);
  }

  void _onResponse(
    Response response,
    ResponseInterceptorHandler handler,
  ) {
    handler.next(response);
  }

  void _onError(
    DioException error,
    ErrorInterceptorHandler handler,
  ) async {
    switch (error.type) {
      case DioExceptionType.connectionTimeout:
      case DioExceptionType.sendTimeout:
      case DioExceptionType.receiveTimeout:
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
            // Check if this is a refresh token request to avoid infinite loop
            final isRefreshRequest = error.requestOptions.path.contains('/auth/refresh');

            if (!isRefreshRequest) {
              // Try to refresh the token
              final success = await _refreshToken();

              if (success) {
                // Retry the original request with new token
                try {
                  final response = await _retryRequest(error.requestOptions);
                  handler.resolve(response);
                  return;
                } catch (e) {
                  // If retry fails, reject with authentication error
                  await _clearTokens();
                }
              } else {
                // Refresh failed, clear tokens and reject
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
  Future<bool> _refreshToken() async {
    if (_isRefreshing) {
      // If already refreshing, wait for it to complete
      return await _waitForRefresh();
    }

    _isRefreshing = true;

    try {
      final refreshToken = await _secureStorage.read(key: AppConstants.refreshTokenKey);
      if (refreshToken == null) {
        return false;
      }

      final response = await _dio.post(
        '/auth/refresh',
        data: {'refresh_token': refreshToken},
        options: Options(
          headers: {'Content-Type': 'application/json'},
        ),
      );

      if (response.statusCode == 200) {
        final newAccessToken = response.data['access_token'];
        final newRefreshToken = response.data['refresh_token'];

        await _secureStorage.write(key: AppConstants.accessTokenKey, value: newAccessToken);
        if (newRefreshToken != null) {
          await _secureStorage.write(key: AppConstants.refreshTokenKey, value: newRefreshToken);
        }

        // Retry queued requests
        _retryQueuedRequests();

        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Token refresh failed: $e');
      return false;
    } finally {
      _isRefreshing = false;
    }
  }

  Future<bool> _waitForRefresh() async {
    int attempts = 0;
    const maxAttempts = 50; // 5 seconds max wait

    while (_isRefreshing && attempts < maxAttempts) {
      await Future.delayed(const Duration(milliseconds: 100));
      attempts++;
    }

    return !_isRefreshing; // Return true if refresh completed (not failed)
  }

  void _retryQueuedRequests() {
    for (final request in _queuedRequests) {
      request();
    }
    _queuedRequests.clear();
  }

  Future<Response> _retryRequest(RequestOptions options) async {
    final token = await _secureStorage.read(key: AppConstants.accessTokenKey);
    if (token != null) {
      options.headers['Authorization'] = 'Bearer $token';
    }

    return _dio.fetch(options);
  }

  Future<void> _clearTokens() async {
    await _secureStorage.delete(key: AppConstants.accessTokenKey);
    await _secureStorage.delete(key: AppConstants.refreshTokenKey);
    await _secureStorage.delete(key: AppConstants.userProfileKey);
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